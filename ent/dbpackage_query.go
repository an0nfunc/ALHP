// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"git.harting.dev/ALHP/ALHP.GO/ent/dbpackage"
	"git.harting.dev/ALHP/ALHP.GO/ent/predicate"
)

// DbPackageQuery is the builder for querying DbPackage entities.
type DbPackageQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.DbPackage
	modifiers  []func(*sql.Selector)
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the DbPackageQuery builder.
func (dpq *DbPackageQuery) Where(ps ...predicate.DbPackage) *DbPackageQuery {
	dpq.predicates = append(dpq.predicates, ps...)
	return dpq
}

// Limit adds a limit step to the query.
func (dpq *DbPackageQuery) Limit(limit int) *DbPackageQuery {
	dpq.limit = &limit
	return dpq
}

// Offset adds an offset step to the query.
func (dpq *DbPackageQuery) Offset(offset int) *DbPackageQuery {
	dpq.offset = &offset
	return dpq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (dpq *DbPackageQuery) Unique(unique bool) *DbPackageQuery {
	dpq.unique = &unique
	return dpq
}

// Order adds an order step to the query.
func (dpq *DbPackageQuery) Order(o ...OrderFunc) *DbPackageQuery {
	dpq.order = append(dpq.order, o...)
	return dpq
}

// First returns the first DbPackage entity from the query.
// Returns a *NotFoundError when no DbPackage was found.
func (dpq *DbPackageQuery) First(ctx context.Context) (*DbPackage, error) {
	nodes, err := dpq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{dbpackage.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (dpq *DbPackageQuery) FirstX(ctx context.Context) *DbPackage {
	node, err := dpq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first DbPackage ID from the query.
// Returns a *NotFoundError when no DbPackage ID was found.
func (dpq *DbPackageQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dpq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{dbpackage.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (dpq *DbPackageQuery) FirstIDX(ctx context.Context) int {
	id, err := dpq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single DbPackage entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one DbPackage entity is found.
// Returns a *NotFoundError when no DbPackage entities are found.
func (dpq *DbPackageQuery) Only(ctx context.Context) (*DbPackage, error) {
	nodes, err := dpq.Limit(2).All(ctx)
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
func (dpq *DbPackageQuery) OnlyX(ctx context.Context) *DbPackage {
	node, err := dpq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only DbPackage ID in the query.
// Returns a *NotSingularError when more than one DbPackage ID is found.
// Returns a *NotFoundError when no entities are found.
func (dpq *DbPackageQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dpq.Limit(2).IDs(ctx); err != nil {
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
func (dpq *DbPackageQuery) OnlyIDX(ctx context.Context) int {
	id, err := dpq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of DbPackages.
func (dpq *DbPackageQuery) All(ctx context.Context) ([]*DbPackage, error) {
	if err := dpq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return dpq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (dpq *DbPackageQuery) AllX(ctx context.Context) []*DbPackage {
	nodes, err := dpq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of DbPackage IDs.
func (dpq *DbPackageQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := dpq.Select(dbpackage.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (dpq *DbPackageQuery) IDsX(ctx context.Context) []int {
	ids, err := dpq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (dpq *DbPackageQuery) Count(ctx context.Context) (int, error) {
	if err := dpq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return dpq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (dpq *DbPackageQuery) CountX(ctx context.Context) int {
	count, err := dpq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (dpq *DbPackageQuery) Exist(ctx context.Context) (bool, error) {
	if err := dpq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return dpq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (dpq *DbPackageQuery) ExistX(ctx context.Context) bool {
	exist, err := dpq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the DbPackageQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (dpq *DbPackageQuery) Clone() *DbPackageQuery {
	if dpq == nil {
		return nil
	}
	return &DbPackageQuery{
		config:     dpq.config,
		limit:      dpq.limit,
		offset:     dpq.offset,
		order:      append([]OrderFunc{}, dpq.order...),
		predicates: append([]predicate.DbPackage{}, dpq.predicates...),
		// clone intermediate query.
		sql:    dpq.sql.Clone(),
		path:   dpq.path,
		unique: dpq.unique,
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
//	client.DbPackage.Query().
//		GroupBy(dbpackage.FieldPkgbase).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (dpq *DbPackageQuery) GroupBy(field string, fields ...string) *DbPackageGroupBy {
	grbuild := &DbPackageGroupBy{config: dpq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := dpq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return dpq.sqlQuery(ctx), nil
	}
	grbuild.label = dbpackage.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
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
//	client.DbPackage.Query().
//		Select(dbpackage.FieldPkgbase).
//		Scan(ctx, &v)
func (dpq *DbPackageQuery) Select(fields ...string) *DbPackageSelect {
	dpq.fields = append(dpq.fields, fields...)
	selbuild := &DbPackageSelect{DbPackageQuery: dpq}
	selbuild.label = dbpackage.Label
	selbuild.flds, selbuild.scan = &dpq.fields, selbuild.Scan
	return selbuild
}

// Aggregate returns a DbPackageSelect configured with the given aggregations.
func (dpq *DbPackageQuery) Aggregate(fns ...AggregateFunc) *DbPackageSelect {
	return dpq.Select().Aggregate(fns...)
}

func (dpq *DbPackageQuery) prepareQuery(ctx context.Context) error {
	for _, f := range dpq.fields {
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

func (dpq *DbPackageQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*DbPackage, error) {
	var (
		nodes = []*DbPackage{}
		_spec = dpq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*DbPackage).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &DbPackage{config: dpq.config}
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

func (dpq *DbPackageQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := dpq.querySpec()
	if len(dpq.modifiers) > 0 {
		_spec.Modifiers = dpq.modifiers
	}
	_spec.Node.Columns = dpq.fields
	if len(dpq.fields) > 0 {
		_spec.Unique = dpq.unique != nil && *dpq.unique
	}
	return sqlgraph.CountNodes(ctx, dpq.driver, _spec)
}

func (dpq *DbPackageQuery) sqlExist(ctx context.Context) (bool, error) {
	switch _, err := dpq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

func (dpq *DbPackageQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   dbpackage.Table,
			Columns: dbpackage.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: dbpackage.FieldID,
			},
		},
		From:   dpq.sql,
		Unique: true,
	}
	if unique := dpq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := dpq.fields; len(fields) > 0 {
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
	if limit := dpq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := dpq.offset; offset != nil {
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

func (dpq *DbPackageQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(dpq.driver.Dialect())
	t1 := builder.Table(dbpackage.Table)
	columns := dpq.fields
	if len(columns) == 0 {
		columns = dbpackage.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if dpq.sql != nil {
		selector = dpq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if dpq.unique != nil && *dpq.unique {
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
	if offset := dpq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := dpq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// Modify adds a query modifier for attaching custom logic to queries.
func (dpq *DbPackageQuery) Modify(modifiers ...func(s *sql.Selector)) *DbPackageSelect {
	dpq.modifiers = append(dpq.modifiers, modifiers...)
	return dpq.Select()
}

// DbPackageGroupBy is the group-by builder for DbPackage entities.
type DbPackageGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (dpgb *DbPackageGroupBy) Aggregate(fns ...AggregateFunc) *DbPackageGroupBy {
	dpgb.fns = append(dpgb.fns, fns...)
	return dpgb
}

// Scan applies the group-by query and scans the result into the given value.
func (dpgb *DbPackageGroupBy) Scan(ctx context.Context, v any) error {
	query, err := dpgb.path(ctx)
	if err != nil {
		return err
	}
	dpgb.sql = query
	return dpgb.sqlScan(ctx, v)
}

func (dpgb *DbPackageGroupBy) sqlScan(ctx context.Context, v any) error {
	for _, f := range dpgb.fields {
		if !dbpackage.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := dpgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := dpgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (dpgb *DbPackageGroupBy) sqlQuery() *sql.Selector {
	selector := dpgb.sql.Select()
	aggregation := make([]string, 0, len(dpgb.fns))
	for _, fn := range dpgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(dpgb.fields)+len(dpgb.fns))
		for _, f := range dpgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(dpgb.fields...)...)
}

// DbPackageSelect is the builder for selecting fields of DbPackage entities.
type DbPackageSelect struct {
	*DbPackageQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (dps *DbPackageSelect) Aggregate(fns ...AggregateFunc) *DbPackageSelect {
	dps.fns = append(dps.fns, fns...)
	return dps
}

// Scan applies the selector query and scans the result into the given value.
func (dps *DbPackageSelect) Scan(ctx context.Context, v any) error {
	if err := dps.prepareQuery(ctx); err != nil {
		return err
	}
	dps.sql = dps.DbPackageQuery.sqlQuery(ctx)
	return dps.sqlScan(ctx, v)
}

func (dps *DbPackageSelect) sqlScan(ctx context.Context, v any) error {
	aggregation := make([]string, 0, len(dps.fns))
	for _, fn := range dps.fns {
		aggregation = append(aggregation, fn(dps.sql))
	}
	switch n := len(*dps.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		dps.sql.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		dps.sql.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := dps.sql.Query()
	if err := dps.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// Modify adds a query modifier for attaching custom logic to queries.
func (dps *DbPackageSelect) Modify(modifiers ...func(s *sql.Selector)) *DbPackageSelect {
	dps.modifiers = append(dps.modifiers, modifiers...)
	return dps
}
