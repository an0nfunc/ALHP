// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"somegit.dev/ALHP/ALHP.GO/ent/predicate"
)

// DBPackageQuery is the builder for querying DBPackage entities.
type DBPackageQuery struct {
	config
	ctx        *QueryContext
	order      []dbpackage.OrderOption
	inters     []Interceptor
	predicates []predicate.DBPackage
	modifiers  []func(*sql.Selector)
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the DBPackageQuery builder.
func (dpq *DBPackageQuery) Where(ps ...predicate.DBPackage) *DBPackageQuery {
	dpq.predicates = append(dpq.predicates, ps...)
	return dpq
}

// Limit the number of records to be returned by this query.
func (dpq *DBPackageQuery) Limit(limit int) *DBPackageQuery {
	dpq.ctx.Limit = &limit
	return dpq
}

// Offset to start from.
func (dpq *DBPackageQuery) Offset(offset int) *DBPackageQuery {
	dpq.ctx.Offset = &offset
	return dpq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (dpq *DBPackageQuery) Unique(unique bool) *DBPackageQuery {
	dpq.ctx.Unique = &unique
	return dpq
}

// Order specifies how the records should be ordered.
func (dpq *DBPackageQuery) Order(o ...dbpackage.OrderOption) *DBPackageQuery {
	dpq.order = append(dpq.order, o...)
	return dpq
}

// First returns the first DBPackage entity from the query.
// Returns a *NotFoundError when no DBPackage was found.
func (dpq *DBPackageQuery) First(ctx context.Context) (*DBPackage, error) {
	nodes, err := dpq.Limit(1).All(setContextOp(ctx, dpq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{dbpackage.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (dpq *DBPackageQuery) FirstX(ctx context.Context) *DBPackage {
	node, err := dpq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first DBPackage ID from the query.
// Returns a *NotFoundError when no DBPackage ID was found.
func (dpq *DBPackageQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dpq.Limit(1).IDs(setContextOp(ctx, dpq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{dbpackage.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (dpq *DBPackageQuery) FirstIDX(ctx context.Context) int {
	id, err := dpq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single DBPackage entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one DBPackage entity is found.
// Returns a *NotFoundError when no DBPackage entities are found.
func (dpq *DBPackageQuery) Only(ctx context.Context) (*DBPackage, error) {
	nodes, err := dpq.Limit(2).All(setContextOp(ctx, dpq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{dbpackage.Label}
	default:
		return nil, &NotSingularError{dbpackage.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (dpq *DBPackageQuery) OnlyX(ctx context.Context) *DBPackage {
	node, err := dpq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only DBPackage ID in the query.
// Returns a *NotSingularError when more than one DBPackage ID is found.
// Returns a *NotFoundError when no entities are found.
func (dpq *DBPackageQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dpq.Limit(2).IDs(setContextOp(ctx, dpq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{dbpackage.Label}
	default:
		err = &NotSingularError{dbpackage.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (dpq *DBPackageQuery) OnlyIDX(ctx context.Context) int {
	id, err := dpq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of DBPackages.
func (dpq *DBPackageQuery) All(ctx context.Context) ([]*DBPackage, error) {
	ctx = setContextOp(ctx, dpq.ctx, ent.OpQueryAll)
	if err := dpq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*DBPackage, *DBPackageQuery]()
	return withInterceptors[[]*DBPackage](ctx, dpq, qr, dpq.inters)
}

// AllX is like All, but panics if an error occurs.
func (dpq *DBPackageQuery) AllX(ctx context.Context) []*DBPackage {
	nodes, err := dpq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of DBPackage IDs.
func (dpq *DBPackageQuery) IDs(ctx context.Context) (ids []int, err error) {
	if dpq.ctx.Unique == nil && dpq.path != nil {
		dpq.Unique(true)
	}
	ctx = setContextOp(ctx, dpq.ctx, ent.OpQueryIDs)
	if err = dpq.Select(dbpackage.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (dpq *DBPackageQuery) IDsX(ctx context.Context) []int {
	ids, err := dpq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (dpq *DBPackageQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, dpq.ctx, ent.OpQueryCount)
	if err := dpq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, dpq, querierCount[*DBPackageQuery](), dpq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (dpq *DBPackageQuery) CountX(ctx context.Context) int {
	count, err := dpq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (dpq *DBPackageQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, dpq.ctx, ent.OpQueryExist)
	switch _, err := dpq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (dpq *DBPackageQuery) ExistX(ctx context.Context) bool {
	exist, err := dpq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the DBPackageQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (dpq *DBPackageQuery) Clone() *DBPackageQuery {
	if dpq == nil {
		return nil
	}
	return &DBPackageQuery{
		config:     dpq.config,
		ctx:        dpq.ctx.Clone(),
		order:      append([]dbpackage.OrderOption{}, dpq.order...),
		inters:     append([]Interceptor{}, dpq.inters...),
		predicates: append([]predicate.DBPackage{}, dpq.predicates...),
		// clone intermediate query.
		sql:  dpq.sql.Clone(),
		path: dpq.path,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Pkgbase string `json:"pkgbase,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.DBPackage.Query().
//		GroupBy(dbpackage.FieldPkgbase).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (dpq *DBPackageQuery) GroupBy(field string, fields ...string) *DBPackageGroupBy {
	dpq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &DBPackageGroupBy{build: dpq}
	grbuild.flds = &dpq.ctx.Fields
	grbuild.label = dbpackage.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Pkgbase string `json:"pkgbase,omitempty"`
//	}
//
//	client.DBPackage.Query().
//		Select(dbpackage.FieldPkgbase).
//		Scan(ctx, &v)
func (dpq *DBPackageQuery) Select(fields ...string) *DBPackageSelect {
	dpq.ctx.Fields = append(dpq.ctx.Fields, fields...)
	sbuild := &DBPackageSelect{DBPackageQuery: dpq}
	sbuild.label = dbpackage.Label
	sbuild.flds, sbuild.scan = &dpq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a DBPackageSelect configured with the given aggregations.
func (dpq *DBPackageQuery) Aggregate(fns ...AggregateFunc) *DBPackageSelect {
	return dpq.Select().Aggregate(fns...)
}

func (dpq *DBPackageQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range dpq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, dpq); err != nil {
				return err
			}
		}
	}
	for _, f := range dpq.ctx.Fields {
		if !dbpackage.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if dpq.path != nil {
		prev, err := dpq.path(ctx)
		if err != nil {
			return err
		}
		dpq.sql = prev
	}
	return nil
}

func (dpq *DBPackageQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*DBPackage, error) {
	var (
		nodes = []*DBPackage{}
		_spec = dpq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*DBPackage).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &DBPackage{config: dpq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	if len(dpq.modifiers) > 0 {
		_spec.Modifiers = dpq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, dpq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (dpq *DBPackageQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := dpq.querySpec()
	if len(dpq.modifiers) > 0 {
		_spec.Modifiers = dpq.modifiers
	}
	_spec.Node.Columns = dpq.ctx.Fields
	if len(dpq.ctx.Fields) > 0 {
		_spec.Unique = dpq.ctx.Unique != nil && *dpq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, dpq.driver, _spec)
}

func (dpq *DBPackageQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(dbpackage.Table, dbpackage.Columns, sqlgraph.NewFieldSpec(dbpackage.FieldID, field.TypeInt))
	_spec.From = dpq.sql
	if unique := dpq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if dpq.path != nil {
		_spec.Unique = true
	}
	if fields := dpq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, dbpackage.FieldID)
		for i := range fields {
			if fields[i] != dbpackage.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := dpq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := dpq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := dpq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := dpq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (dpq *DBPackageQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(dpq.driver.Dialect())
	t1 := builder.Table(dbpackage.Table)
	columns := dpq.ctx.Fields
	if len(columns) == 0 {
		columns = dbpackage.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if dpq.sql != nil {
		selector = dpq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if dpq.ctx.Unique != nil && *dpq.ctx.Unique {
		selector.Distinct()
	}
	for _, m := range dpq.modifiers {
		m(selector)
	}
	for _, p := range dpq.predicates {
		p(selector)
	}
	for _, p := range dpq.order {
		p(selector)
	}
	if offset := dpq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := dpq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// Modify adds a query modifier for attaching custom logic to queries.
func (dpq *DBPackageQuery) Modify(modifiers ...func(s *sql.Selector)) *DBPackageSelect {
	dpq.modifiers = append(dpq.modifiers, modifiers...)
	return dpq.Select()
}

// DBPackageGroupBy is the group-by builder for DBPackage entities.
type DBPackageGroupBy struct {
	selector
	build *DBPackageQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (dpgb *DBPackageGroupBy) Aggregate(fns ...AggregateFunc) *DBPackageGroupBy {
	dpgb.fns = append(dpgb.fns, fns...)
	return dpgb
}

// Scan applies the selector query and scans the result into the given value.
func (dpgb *DBPackageGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, dpgb.build.ctx, ent.OpQueryGroupBy)
	if err := dpgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*DBPackageQuery, *DBPackageGroupBy](ctx, dpgb.build, dpgb, dpgb.build.inters, v)
}

func (dpgb *DBPackageGroupBy) sqlScan(ctx context.Context, root *DBPackageQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(dpgb.fns))
	for _, fn := range dpgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*dpgb.flds)+len(dpgb.fns))
		for _, f := range *dpgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*dpgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := dpgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// DBPackageSelect is the builder for selecting fields of DBPackage entities.
type DBPackageSelect struct {
	*DBPackageQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (dps *DBPackageSelect) Aggregate(fns ...AggregateFunc) *DBPackageSelect {
	dps.fns = append(dps.fns, fns...)
	return dps
}

// Scan applies the selector query and scans the result into the given value.
func (dps *DBPackageSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, dps.ctx, ent.OpQuerySelect)
	if err := dps.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*DBPackageQuery, *DBPackageSelect](ctx, dps.DBPackageQuery, dps, dps.inters, v)
}

func (dps *DBPackageSelect) sqlScan(ctx context.Context, root *DBPackageQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(dps.fns))
	for _, fn := range dps.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*dps.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := dps.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// Modify adds a query modifier for attaching custom logic to queries.
func (dps *DBPackageSelect) Modify(modifiers ...func(s *sql.Selector)) *DBPackageSelect {
	dps.modifiers = append(dps.modifiers, modifiers...)
	return dps
}
