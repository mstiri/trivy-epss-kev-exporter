package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	appslisters "k8s.io/client-go/listers/apps/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

// vrGVR is the VulnerabilityReport resource: aquasecurity.github.io/v1alpha1.
var vrGVR = schema.GroupVersionResource{
	Group:    "aquasecurity.github.io",
	Version:  "v1alpha1",
	Resource: "vulnerabilityreports",
}

// ReconcileFunc handles one report key. When the report still exists, rep is the
// decoded object and w is its RESOLVED workload (roll-up already applied); when
// it has been deleted, rep is nil, w is zero, and exists is false (delete the
// key's series). It is the step-6 glue (enrich → metrics) injected here.
type ReconcileFunc func(key string, rep *report.VulnerabilityReport, w report.Workload, exists bool) error

// Options configures the controller.
type Options struct {
	// Namespaces is an optional allowlist; empty means all namespaces.
	Namespaces []string
	// ResyncInterval drives informer resync; 0 disables it (the default).
	ResyncInterval time.Duration
	// Workers is the number of concurrent workqueue workers (default 2).
	Workers int
	// EnableRollup turns on ReplicaSet→Deployment workload resolution, which
	// requires the ReplicaSet lister (and read RBAC on replicasets).
	EnableRollup bool
}

// Controller wires the informers, the workqueue, and the reconcile callback.
type Controller struct {
	clients   *Clients
	opts      Options
	reconcile ReconcileFunc
	onSynced  func(bool)

	vrFactory  dynamicinformer.DynamicSharedInformerFactory
	vrInformer cache.SharedIndexInformer

	rsFactory  informers.SharedInformerFactory
	rsInformer cache.SharedIndexInformer
	rsLister   appslisters.ReplicaSetLister

	resolver Resolver
	queue    workqueue.TypedRateLimitingInterface[string]
	nsAllow  map[string]struct{}
	workers  int
}

// New constructs the controller: it registers the VulnerabilityReport informer
// (all namespaces, filtered to the allowlist on enqueue) and, when roll-up is
// enabled, the ReplicaSet informer/lister that backs workload resolution.
func New(clients *Clients, reconcile ReconcileFunc, onSynced func(bool), opts Options) (*Controller, error) {
	if reconcile == nil {
		return nil, errors.New("controller: reconcile func is required")
	}
	if onSynced == nil {
		onSynced = func(bool) {}
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = 2
	}

	c := &Controller{
		clients:   clients,
		opts:      opts,
		reconcile: reconcile,
		onSynced:  onSynced,
		resolver:  identityResolver{},
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "vulnerabilityreports"},
		),
		nsAllow: toSet(opts.Namespaces),
		workers: workers,
	}

	// VulnerabilityReport informer (dynamic; all namespaces, allowlist applied
	// in the event handler so any namespace count works with one factory).
	c.vrFactory = dynamicinformer.NewDynamicSharedInformerFactory(clients.Dynamic, opts.ResyncInterval)
	c.vrInformer = c.vrFactory.ForResource(vrGVR).Informer()
	if _, err := c.vrInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.enqueue,
		UpdateFunc: func(_, newObj any) { c.enqueue(newObj) },
		DeleteFunc: c.enqueue,
	}); err != nil {
		return nil, fmt.Errorf("controller: add event handler: %w", err)
	}

	if opts.EnableRollup {
		c.rsFactory = informers.NewSharedInformerFactory(clients.Kube, opts.ResyncInterval)
		rs := c.rsFactory.Apps().V1().ReplicaSets()
		c.rsInformer = rs.Informer()
		// Trim cached ReplicaSets to metadata: we only read ownerReferences, so
		// dropping Spec (the pod template) and Status keeps the cache lean.
		if err := c.rsInformer.SetTransform(trimReplicaSet); err != nil {
			return nil, fmt.Errorf("controller: set replicaset transform: %w", err)
		}
		c.rsLister = rs.Lister()
		c.resolver = replicaSetResolver{get: func(ns, name string) (*appsv1.ReplicaSet, error) {
			return c.rsLister.ReplicaSets(ns).Get(name)
		}}
	}

	return c, nil
}

// Run starts the informers, waits for cache sync, then runs the workers until
// ctx is cancelled. It reports sync state through onSynced (for cache_synced).
func (c *Controller) Run(ctx context.Context) error {
	defer c.queue.ShutDown()

	c.vrFactory.Start(ctx.Done())
	if c.rsFactory != nil {
		c.rsFactory.Start(ctx.Done())
	}

	synced := []cache.InformerSynced{c.vrInformer.HasSynced}
	if c.rsInformer != nil {
		synced = append(synced, c.rsInformer.HasSynced)
	}
	if !cache.WaitForCacheSync(ctx.Done(), synced...) {
		c.onSynced(false)
		return errors.New("controller: cache sync failed")
	}
	c.onSynced(true)
	klog.InfoS("informer caches synced; starting workers", "workers", c.workers)

	// Shut the queue down on cancel so blocked workers wake and exit.
	go func() {
		<-ctx.Done()
		c.queue.ShutDown()
	}()

	done := make(chan struct{}, c.workers)
	for range c.workers {
		go func() {
			for c.processNext() {
			}
			done <- struct{}{}
		}()
	}
	for range c.workers {
		<-done
	}
	return nil
}

// enqueue derives the report key and adds it to the queue, skipping namespaces
// outside the allowlist. Handles delete tombstones.
func (c *Controller) enqueue(obj any) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.ErrorS(err, "deriving object key")
		return
	}
	ns, _, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		klog.ErrorS(err, "splitting object key", "key", key)
		return
	}
	if !c.allowed(ns) {
		return
	}
	c.queue.Add(key)
}

// EnqueueAll sweeps the warm cache and enqueues every in-scope report key. This
// is TRIGGER B: a feed refresher calls it when feed CONTENT changed, so every
// report re-enriches against the new EPSS/KEV data even though no CRD changed.
// Re-enqueuing keys already in the queue is free (the workqueue dedups).
func (c *Controller) EnqueueAll() {
	for _, key := range c.vrInformer.GetIndexer().ListKeys() {
		ns, _, err := cache.SplitMetaNamespaceKey(key)
		if err != nil {
			continue
		}
		if c.allowed(ns) {
			c.queue.Add(key)
		}
	}
}

func (c *Controller) allowed(namespace string) bool {
	if len(c.nsAllow) == 0 {
		return true
	}
	_, ok := c.nsAllow[namespace]
	return ok
}

func (c *Controller) processNext() bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)

	if err := c.process(key); err != nil {
		// Transient: requeue with backoff.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "reconcile failed, requeuing", "key", key)
		return true
	}
	c.queue.Forget(key)
	return true
}

// process looks the key up in the warm cache and dispatches to the reconcile
// callback. A cache miss means the report was deleted → exists=false.
func (c *Controller) process(key string) error {
	item, exists, err := c.vrInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("indexer get %q: %w", key, err)
	}
	if !exists {
		return c.reconcile(key, nil, report.Workload{}, false)
	}
	u, ok := item.(*unstructured.Unstructured)
	if !ok {
		// Not retryable — wrong type in the store should never happen.
		klog.ErrorS(fmt.Errorf("unexpected type %T", item), "skipping object", "key", key)
		return nil
	}
	rep, err := reportFromUnstructured(u)
	if err != nil {
		// Malformed object — requeueing won't fix it; drop it.
		klog.ErrorS(err, "skipping unparseable report", "key", key)
		return nil
	}
	w := c.resolver.Resolve(rep.Workload())
	return c.reconcile(key, rep, w, true)
}

// trimReplicaSet drops everything but metadata from a cached ReplicaSet; we only
// read its ownerReferences for roll-up.
func trimReplicaSet(obj any) (any, error) {
	rs, ok := obj.(*appsv1.ReplicaSet)
	if !ok {
		return obj, nil
	}
	rs.Spec = appsv1.ReplicaSetSpec{}
	rs.Status = appsv1.ReplicaSetStatus{}
	rs.ManagedFields = nil
	return rs, nil
}

func toSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	s := make(map[string]struct{}, len(items))
	for _, it := range items {
		s[it] = struct{}{}
	}
	return s
}
