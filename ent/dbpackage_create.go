// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
)

// DBPackageCreate is the builder for creating a DBPackage entity.
type DBPackageCreate struct {
	config
	mutation *DBPackageMutation
	hooks    []Hook
}

// SetPkgbase sets the "pkgbase" field.
func (dpc *DBPackageCreate) SetPkgbase(s string) *DBPackageCreate {
	dpc.mutation.SetPkgbase(s)
	return dpc
}

// SetPackages sets the "packages" field.
func (dpc *DBPackageCreate) SetPackages(s []string) *DBPackageCreate {
	dpc.mutation.SetPackages(s)
	return dpc
}

// SetStatus sets the "status" field.
func (dpc *DBPackageCreate) SetStatus(d dbpackage.Status) *DBPackageCreate {
	dpc.mutation.SetStatus(d)
	return dpc
}

// SetNillableStatus sets the "status" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableStatus(d *dbpackage.Status) *DBPackageCreate {
	if d != nil {
		dpc.SetStatus(*d)
	}
	return dpc
}

// SetSkipReason sets the "skip_reason" field.
func (dpc *DBPackageCreate) SetSkipReason(s string) *DBPackageCreate {
	dpc.mutation.SetSkipReason(s)
	return dpc
}

// SetNillableSkipReason sets the "skip_reason" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableSkipReason(s *string) *DBPackageCreate {
	if s != nil {
		dpc.SetSkipReason(*s)
	}
	return dpc
}

// SetRepository sets the "repository" field.
func (dpc *DBPackageCreate) SetRepository(d dbpackage.Repository) *DBPackageCreate {
	dpc.mutation.SetRepository(d)
	return dpc
}

// SetMarch sets the "march" field.
func (dpc *DBPackageCreate) SetMarch(s string) *DBPackageCreate {
	dpc.mutation.SetMarch(s)
	return dpc
}

// SetVersion sets the "version" field.
func (dpc *DBPackageCreate) SetVersion(s string) *DBPackageCreate {
	dpc.mutation.SetVersion(s)
	return dpc
}

// SetNillableVersion sets the "version" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableVersion(s *string) *DBPackageCreate {
	if s != nil {
		dpc.SetVersion(*s)
	}
	return dpc
}

// SetRepoVersion sets the "repo_version" field.
func (dpc *DBPackageCreate) SetRepoVersion(s string) *DBPackageCreate {
	dpc.mutation.SetRepoVersion(s)
	return dpc
}

// SetNillableRepoVersion sets the "repo_version" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableRepoVersion(s *string) *DBPackageCreate {
	if s != nil {
		dpc.SetRepoVersion(*s)
	}
	return dpc
}

// SetBuildTimeStart sets the "build_time_start" field.
func (dpc *DBPackageCreate) SetBuildTimeStart(t time.Time) *DBPackageCreate {
	dpc.mutation.SetBuildTimeStart(t)
	return dpc
}

// SetNillableBuildTimeStart sets the "build_time_start" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableBuildTimeStart(t *time.Time) *DBPackageCreate {
	if t != nil {
		dpc.SetBuildTimeStart(*t)
	}
	return dpc
}

// SetUpdated sets the "updated" field.
func (dpc *DBPackageCreate) SetUpdated(t time.Time) *DBPackageCreate {
	dpc.mutation.SetUpdated(t)
	return dpc
}

// SetNillableUpdated sets the "updated" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableUpdated(t *time.Time) *DBPackageCreate {
	if t != nil {
		dpc.SetUpdated(*t)
	}
	return dpc
}

// SetLto sets the "lto" field.
func (dpc *DBPackageCreate) SetLto(d dbpackage.Lto) *DBPackageCreate {
	dpc.mutation.SetLto(d)
	return dpc
}

// SetNillableLto sets the "lto" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableLto(d *dbpackage.Lto) *DBPackageCreate {
	if d != nil {
		dpc.SetLto(*d)
	}
	return dpc
}

// SetLastVersionBuild sets the "last_version_build" field.
func (dpc *DBPackageCreate) SetLastVersionBuild(s string) *DBPackageCreate {
	dpc.mutation.SetLastVersionBuild(s)
	return dpc
}

// SetNillableLastVersionBuild sets the "last_version_build" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableLastVersionBuild(s *string) *DBPackageCreate {
	if s != nil {
		dpc.SetLastVersionBuild(*s)
	}
	return dpc
}

// SetLastVerified sets the "last_verified" field.
func (dpc *DBPackageCreate) SetLastVerified(t time.Time) *DBPackageCreate {
	dpc.mutation.SetLastVerified(t)
	return dpc
}

// SetNillableLastVerified sets the "last_verified" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableLastVerified(t *time.Time) *DBPackageCreate {
	if t != nil {
		dpc.SetLastVerified(*t)
	}
	return dpc
}

// SetDebugSymbols sets the "debug_symbols" field.
func (dpc *DBPackageCreate) SetDebugSymbols(ds dbpackage.DebugSymbols) *DBPackageCreate {
	dpc.mutation.SetDebugSymbols(ds)
	return dpc
}

// SetNillableDebugSymbols sets the "debug_symbols" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableDebugSymbols(ds *dbpackage.DebugSymbols) *DBPackageCreate {
	if ds != nil {
		dpc.SetDebugSymbols(*ds)
	}
	return dpc
}

// SetMaxRss sets the "max_rss" field.
func (dpc *DBPackageCreate) SetMaxRss(i int64) *DBPackageCreate {
	dpc.mutation.SetMaxRss(i)
	return dpc
}

// SetNillableMaxRss sets the "max_rss" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableMaxRss(i *int64) *DBPackageCreate {
	if i != nil {
		dpc.SetMaxRss(*i)
	}
	return dpc
}

// SetUTime sets the "u_time" field.
func (dpc *DBPackageCreate) SetUTime(i int64) *DBPackageCreate {
	dpc.mutation.SetUTime(i)
	return dpc
}

// SetNillableUTime sets the "u_time" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableUTime(i *int64) *DBPackageCreate {
	if i != nil {
		dpc.SetUTime(*i)
	}
	return dpc
}

// SetSTime sets the "s_time" field.
func (dpc *DBPackageCreate) SetSTime(i int64) *DBPackageCreate {
	dpc.mutation.SetSTime(i)
	return dpc
}

// SetNillableSTime sets the "s_time" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableSTime(i *int64) *DBPackageCreate {
	if i != nil {
		dpc.SetSTime(*i)
	}
	return dpc
}

// SetIoIn sets the "io_in" field.
func (dpc *DBPackageCreate) SetIoIn(i int64) *DBPackageCreate {
	dpc.mutation.SetIoIn(i)
	return dpc
}

// SetNillableIoIn sets the "io_in" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableIoIn(i *int64) *DBPackageCreate {
	if i != nil {
		dpc.SetIoIn(*i)
	}
	return dpc
}

// SetIoOut sets the "io_out" field.
func (dpc *DBPackageCreate) SetIoOut(i int64) *DBPackageCreate {
	dpc.mutation.SetIoOut(i)
	return dpc
}

// SetNillableIoOut sets the "io_out" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableIoOut(i *int64) *DBPackageCreate {
	if i != nil {
		dpc.SetIoOut(*i)
	}
	return dpc
}

// SetTagRev sets the "tag_rev" field.
func (dpc *DBPackageCreate) SetTagRev(s string) *DBPackageCreate {
	dpc.mutation.SetTagRev(s)
	return dpc
}

// SetNillableTagRev sets the "tag_rev" field if the given value is not nil.
func (dpc *DBPackageCreate) SetNillableTagRev(s *string) *DBPackageCreate {
	if s != nil {
		dpc.SetTagRev(*s)
	}
	return dpc
}

// Mutation returns the DBPackageMutation object of the builder.
func (dpc *DBPackageCreate) Mutation() *DBPackageMutation {
	return dpc.mutation
}

// Save creates the DBPackage in the database.
func (dpc *DBPackageCreate) Save(ctx context.Context) (*DBPackage, error) {
	dpc.defaults()
	return withHooks(ctx, dpc.sqlSave, dpc.mutation, dpc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (dpc *DBPackageCreate) SaveX(ctx context.Context) *DBPackage {
	v, err := dpc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dpc *DBPackageCreate) Exec(ctx context.Context) error {
	_, err := dpc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dpc *DBPackageCreate) ExecX(ctx context.Context) {
	if err := dpc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (dpc *DBPackageCreate) defaults() {
	if _, ok := dpc.mutation.Status(); !ok {
		v := dbpackage.DefaultStatus
		dpc.mutation.SetStatus(v)
	}
	if _, ok := dpc.mutation.Lto(); !ok {
		v := dbpackage.DefaultLto
		dpc.mutation.SetLto(v)
	}
	if _, ok := dpc.mutation.DebugSymbols(); !ok {
		v := dbpackage.DefaultDebugSymbols
		dpc.mutation.SetDebugSymbols(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (dpc *DBPackageCreate) check() error {
	if _, ok := dpc.mutation.Pkgbase(); !ok {
		return &ValidationError{Name: "pkgbase", err: errors.New(`ent: missing required field "DBPackage.pkgbase"`)}
	}
	if v, ok := dpc.mutation.Pkgbase(); ok {
		if err := dbpackage.PkgbaseValidator(v); err != nil {
			return &ValidationError{Name: "pkgbase", err: fmt.Errorf(`ent: validator failed for field "DBPackage.pkgbase": %w`, err)}
		}
	}
	if v, ok := dpc.mutation.Status(); ok {
		if err := dbpackage.StatusValidator(v); err != nil {
			return &ValidationError{Name: "status", err: fmt.Errorf(`ent: validator failed for field "DBPackage.status": %w`, err)}
		}
	}
	if _, ok := dpc.mutation.Repository(); !ok {
		return &ValidationError{Name: "repository", err: errors.New(`ent: missing required field "DBPackage.repository"`)}
	}
	if v, ok := dpc.mutation.Repository(); ok {
		if err := dbpackage.RepositoryValidator(v); err != nil {
			return &ValidationError{Name: "repository", err: fmt.Errorf(`ent: validator failed for field "DBPackage.repository": %w`, err)}
		}
	}
	if _, ok := dpc.mutation.March(); !ok {
		return &ValidationError{Name: "march", err: errors.New(`ent: missing required field "DBPackage.march"`)}
	}
	if v, ok := dpc.mutation.March(); ok {
		if err := dbpackage.MarchValidator(v); err != nil {
			return &ValidationError{Name: "march", err: fmt.Errorf(`ent: validator failed for field "DBPackage.march": %w`, err)}
		}
	}
	if v, ok := dpc.mutation.Lto(); ok {
		if err := dbpackage.LtoValidator(v); err != nil {
			return &ValidationError{Name: "lto", err: fmt.Errorf(`ent: validator failed for field "DBPackage.lto": %w`, err)}
		}
	}
	if v, ok := dpc.mutation.DebugSymbols(); ok {
		if err := dbpackage.DebugSymbolsValidator(v); err != nil {
			return &ValidationError{Name: "debug_symbols", err: fmt.Errorf(`ent: validator failed for field "DBPackage.debug_symbols": %w`, err)}
		}
	}
	return nil
}

func (dpc *DBPackageCreate) sqlSave(ctx context.Context) (*DBPackage, error) {
	if err := dpc.check(); err != nil {
		return nil, err
	}
	_node, _spec := dpc.createSpec()
	if err := sqlgraph.CreateNode(ctx, dpc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	dpc.mutation.id = &_node.ID
	dpc.mutation.done = true
	return _node, nil
}

func (dpc *DBPackageCreate) createSpec() (*DBPackage, *sqlgraph.CreateSpec) {
	var (
		_node = &DBPackage{config: dpc.config}
		_spec = sqlgraph.NewCreateSpec(dbpackage.Table, sqlgraph.NewFieldSpec(dbpackage.FieldID, field.TypeInt))
	)
	if value, ok := dpc.mutation.Pkgbase(); ok {
		_spec.SetField(dbpackage.FieldPkgbase, field.TypeString, value)
		_node.Pkgbase = value
	}
	if value, ok := dpc.mutation.Packages(); ok {
		_spec.SetField(dbpackage.FieldPackages, field.TypeJSON, value)
		_node.Packages = value
	}
	if value, ok := dpc.mutation.Status(); ok {
		_spec.SetField(dbpackage.FieldStatus, field.TypeEnum, value)
		_node.Status = value
	}
	if value, ok := dpc.mutation.SkipReason(); ok {
		_spec.SetField(dbpackage.FieldSkipReason, field.TypeString, value)
		_node.SkipReason = value
	}
	if value, ok := dpc.mutation.Repository(); ok {
		_spec.SetField(dbpackage.FieldRepository, field.TypeEnum, value)
		_node.Repository = value
	}
	if value, ok := dpc.mutation.March(); ok {
		_spec.SetField(dbpackage.FieldMarch, field.TypeString, value)
		_node.March = value
	}
	if value, ok := dpc.mutation.Version(); ok {
		_spec.SetField(dbpackage.FieldVersion, field.TypeString, value)
		_node.Version = value
	}
	if value, ok := dpc.mutation.RepoVersion(); ok {
		_spec.SetField(dbpackage.FieldRepoVersion, field.TypeString, value)
		_node.RepoVersion = value
	}
	if value, ok := dpc.mutation.BuildTimeStart(); ok {
		_spec.SetField(dbpackage.FieldBuildTimeStart, field.TypeTime, value)
		_node.BuildTimeStart = value
	}
	if value, ok := dpc.mutation.Updated(); ok {
		_spec.SetField(dbpackage.FieldUpdated, field.TypeTime, value)
		_node.Updated = value
	}
	if value, ok := dpc.mutation.Lto(); ok {
		_spec.SetField(dbpackage.FieldLto, field.TypeEnum, value)
		_node.Lto = value
	}
	if value, ok := dpc.mutation.LastVersionBuild(); ok {
		_spec.SetField(dbpackage.FieldLastVersionBuild, field.TypeString, value)
		_node.LastVersionBuild = value
	}
	if value, ok := dpc.mutation.LastVerified(); ok {
		_spec.SetField(dbpackage.FieldLastVerified, field.TypeTime, value)
		_node.LastVerified = value
	}
	if value, ok := dpc.mutation.DebugSymbols(); ok {
		_spec.SetField(dbpackage.FieldDebugSymbols, field.TypeEnum, value)
		_node.DebugSymbols = value
	}
	if value, ok := dpc.mutation.MaxRss(); ok {
		_spec.SetField(dbpackage.FieldMaxRss, field.TypeInt64, value)
		_node.MaxRss = &value
	}
	if value, ok := dpc.mutation.UTime(); ok {
		_spec.SetField(dbpackage.FieldUTime, field.TypeInt64, value)
		_node.UTime = &value
	}
	if value, ok := dpc.mutation.STime(); ok {
		_spec.SetField(dbpackage.FieldSTime, field.TypeInt64, value)
		_node.STime = &value
	}
	if value, ok := dpc.mutation.IoIn(); ok {
		_spec.SetField(dbpackage.FieldIoIn, field.TypeInt64, value)
		_node.IoIn = &value
	}
	if value, ok := dpc.mutation.IoOut(); ok {
		_spec.SetField(dbpackage.FieldIoOut, field.TypeInt64, value)
		_node.IoOut = &value
	}
	if value, ok := dpc.mutation.TagRev(); ok {
		_spec.SetField(dbpackage.FieldTagRev, field.TypeString, value)
		_node.TagRev = &value
	}
	return _node, _spec
}

// DBPackageCreateBulk is the builder for creating many DBPackage entities in bulk.
type DBPackageCreateBulk struct {
	config
	err      error
	builders []*DBPackageCreate
}

// Save creates the DBPackage entities in the database.
func (dpcb *DBPackageCreateBulk) Save(ctx context.Context) ([]*DBPackage, error) {
	if dpcb.err != nil {
		return nil, dpcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(dpcb.builders))
	nodes := make([]*DBPackage, len(dpcb.builders))
	mutators := make([]Mutator, len(dpcb.builders))
	for i := range dpcb.builders {
		func(i int, root context.Context) {
			builder := dpcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*DBPackageMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, dpcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, dpcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, dpcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (dpcb *DBPackageCreateBulk) SaveX(ctx context.Context) []*DBPackage {
	v, err := dpcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dpcb *DBPackageCreateBulk) Exec(ctx context.Context) error {
	_, err := dpcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dpcb *DBPackageCreateBulk) ExecX(ctx context.Context) {
	if err := dpcb.Exec(ctx); err != nil {
		panic(err)
	}
}
