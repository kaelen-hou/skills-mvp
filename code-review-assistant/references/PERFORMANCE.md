# Performance Review Checklist

## Database Operations

### N+1 Query Problem
- [ ] Eager loading used for related data
- [ ] Batch queries instead of loops
- [ ] Query count monitored in development

```python
# BAD: N+1 queries
users = User.objects.all()
for user in users:
    print(user.profile.name)  # Each triggers a query

# GOOD: Eager loading
users = User.objects.select_related('profile').all()
```

### Query Optimization
- [ ] Indexes exist for frequently queried columns
- [ ] SELECT only required columns, not SELECT *
- [ ] Pagination used for large result sets
- [ ] Complex queries analyzed with EXPLAIN

### Connection Management
- [ ] Connection pooling configured
- [ ] Connections properly closed
- [ ] Transactions scoped appropriately
- [ ] No long-running transactions

---

## Memory Management

### Memory Leaks
- [ ] Event listeners removed when not needed
- [ ] Large objects dereferenced when done
- [ ] Circular references avoided or handled
- [ ] Closures don't capture unnecessary scope

```javascript
// BAD: Memory leak
element.addEventListener('click', handler);

// GOOD: Cleanup on unmount
const handler = () => { /* ... */ };
element.addEventListener('click', handler);
// Later: element.removeEventListener('click', handler);
```

### Large Data Handling
- [ ] Streaming used for large files
- [ ] Generators/iterators for large datasets
- [ ] Pagination/chunking for large operations
- [ ] Memory limits considered

---

## Algorithm Efficiency

### Complexity
- [ ] O(n²) or worse algorithms justified
- [ ] Nested loops reviewed for optimization
- [ ] Appropriate data structures used
- [ ] Early exits implemented where possible

```python
# BAD: O(n) lookup
if item in large_list:  # O(n)
    process(item)

# GOOD: O(1) lookup
if item in large_set:  # O(1)
    process(item)
```

### String Operations
- [ ] String concatenation in loops avoided
- [ ] StringBuilder/join() used for multiple concatenations
- [ ] Regex compiled once, reused

---

## Caching

### Cache Strategy
- [ ] Frequently accessed, rarely changing data cached
- [ ] Cache invalidation strategy defined
- [ ] TTL appropriate for data freshness needs
- [ ] Cache warming considered for critical data

### Cache Implementation
- [ ] Cache key collisions prevented
- [ ] Serialization overhead considered
- [ ] Distributed cache for multi-instance deployments

---

## Async & Concurrency

### Async Patterns
- [ ] I/O operations async where possible
- [ ] Promise.all for parallel operations
- [ ] No unnecessary await in loops
- [ ] Proper error handling in async code

```javascript
// BAD: Sequential
for (const id of ids) {
    await fetchData(id);
}

// GOOD: Parallel
await Promise.all(ids.map(id => fetchData(id)));
```

### Resource Pools
- [ ] Thread/worker pools sized appropriately
- [ ] Connection pools configured
- [ ] Backpressure handled for queues

---

## Frontend Performance

### Rendering
- [ ] Unnecessary re-renders prevented
- [ ] Virtual DOM updates optimized
- [ ] Heavy computations memoized
- [ ] Lazy loading for off-screen content

### Bundle Size
- [ ] Tree shaking enabled
- [ ] Code splitting implemented
- [ ] Dependencies size considered
- [ ] Dynamic imports for large features

### Network
- [ ] API calls batched where possible
- [ ] Data prefetching for likely needs
- [ ] Compression enabled
- [ ] CDN used for static assets
