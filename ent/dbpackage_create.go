// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"git.harting.dev/ALHP/ALHP.GO/ent/dbpackage"
)

// DbPackageCreate is the builder for creating a DbPackage entity.
type DbPackageCreate struct {
	config
	mutation *DbPackageMutation
	hooks    []Hook
}

// SetPkgbase sets the "pkgbase" field.
func (dpc *DbPackageCreate) SetPkgbase(s string) *DbPackageCreate {
	dpc.mutation.SetPkgbase(s)
	return dpc
}

// SetPackages sets the "packages" field.
func (dpc *DbPackageCreate) SetPackages(s []string) *DbPackageCreate {
	dpc.mutation.SetPackages(s)
	return dpc
}

// SetStatus sets the "status" field.
func (dpc *DbPackageCreate) SetStatus(d dbpackage.Status) *DbPackageCreate {
	dpc.mutation.SetStatus(d)
	return dpc
}

// SetNillableStatus sets the "status" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableStatus(d *dbpackage.Status) *DbPackageCreate {
	if d != nil {
		dpc.SetStatus(*d)
	}
	return dpc
}

// SetSkipReason sets the "skip_reason" field.
func (dpc *DbPackageCreate) SetSkipReason(s string) *DbPackageCreate {
	dpc.mutation.SetSkipReason(s)
	return dpc
}

// SetNillableSkipReason sets the "skip_reason" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableSkipReason(s *string) *DbPackageCreate {
	if s != nil {
		dpc.SetSkipReason(*s)
	}
	return dpc
}

// SetRepository sets the "repository" field.
func (dpc *DbPackageCreate) SetRepository(d dbpackage.Repository) *DbPackageCreate {
	dpc.mutation.SetRepository(d)
	return dpc
}

// SetMarch sets the "march" field.
func (dpc *DbPackageCreate) SetMarch(s string) *DbPackageCreate {
	dpc.mutation.SetMarch(s)
	return dpc
}

// SetVersion sets the "version" field.
func (dpc *DbPackageCreate) SetVersion(s string) *DbPackageCreate {
	dpc.mutation.SetVersion(s)
	return dpc
}

// SetNillableVersion sets the "version" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableVersion(s *string) *DbPackageCreate {
	if s != nil {
		dpc.SetVersion(*s)
	}
	return dpc
}

// SetRepoVersion sets the "repo_version" field.
func (dpc *DbPackageCreate) SetRepoVersion(s string) *DbPackageCreate {
	dpc.mutation.SetRepoVersion(s)
	return dpc
}

// SetNillableRepoVersion sets the "repo_version" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableRepoVersion(s *string) *DbPackageCreate {
	if s != nil {
		dpc.SetRepoVersion(*s)
	}
	return dpc
}

// SetBuildTimeStart sets the "build_time_start" field.
func (dpc *DbPackageCreate) SetBuildTimeStart(t time.Time) *DbPackageCreate {
	dpc.mutation.SetBuildTimeStart(t)
	return dpc
}

// SetNillableBuildTimeStart sets the "build_time_start" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableBuildTimeStart(t *time.Time) *DbPackageCreate {
	if t != nil {
		dpc.SetBuildTimeStart(*t)
	}
	return dpc
}

// SetUpdated sets the "updated" field.
func (dpc *DbPackageCreate) SetUpdated(t time.Time) *DbPackageCreate {
	dpc.mutation.SetUpdated(t)
	return dpc
}

// SetNillableUpdated sets the "updated" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableUpdated(t *time.Time) *DbPackageCreate {
	if t != nil {
		dpc.SetUpdated(*t)
	}
	return dpc
}

// SetHash sets the "hash" field.
func (dpc *DbPackageCreate) SetHash(s string) *DbPackageCreate {
	dpc.mutation.SetHash(s)
	return dpc
}

// SetNillableHash sets the "hash" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableHash(s *string) *DbPackageCreate {
	if s != nil {
		dpc.SetHash(*s)
	}
	return dpc
}

// SetLto sets the "lto" field.
func (dpc *DbPackageCreate) SetLto(d dbpackage.Lto) *DbPackageCreate {
	dpc.mutation.SetLto(d)
	return dpc
}

// SetNillableLto sets the "lto" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableLto(d *dbpackage.Lto) *DbPackageCreate {
	if d != nil {
		dpc.SetLto(*d)
	}
	return dpc
}

// SetLastVersionBuild sets the "last_version_build" field.
func (dpc *DbPackageCreate) SetLastVersionBuild(s string) *DbPackageCreate {
	dpc.mutation.SetLastVersionBuild(s)
	return dpc
}

// SetNillableLastVersionBuild sets the "last_version_build" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableLastVersionBuild(s *string) *DbPackageCreate {
	if s != nil {
		dpc.SetLastVersionBuild(*s)
	}
	return dpc
}

// SetLastVerified sets the "last_verified" field.
func (dpc *DbPackageCreate) SetLastVerified(t time.Time) *DbPackageCreate {
	dpc.mutation.SetLastVerified(t)
	return dpc
}

// SetNillableLastVerified sets the "last_verified" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableLastVerified(t *time.Time) *DbPackageCreate {
	if t != nil {
		dpc.SetLastVerified(*t)
	}
	return dpc
}

// SetDebugSymbols sets the "debug_symbols" field.
func (dpc *DbPackageCreate) SetDebugSymbols(ds dbpackage.DebugSymbols) *DbPackageCreate {
	dpc.mutation.SetDebugSymbols(ds)
	return dpc
}

// SetNillableDebugSymbols sets the "debug_symbols" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableDebugSymbols(ds *dbpackage.DebugSymbols) *DbPackageCreate {
	if ds != nil {
		dpc.SetDebugSymbols(*ds)
	}
	return dpc
}

// SetMaxRss sets the "max_rss" field.
func (dpc *DbPackageCreate) SetMaxRss(i int64) *DbPackageCreate {
	dpc.mutation.SetMaxRss(i)
	return dpc
}

// SetNillableMaxRss sets the "max_rss" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableMaxRss(i *int64) *DbPackageCreate {
	if i != nil {
		dpc.SetMaxRss(*i)
	}
	return dpc
}

// SetUTime sets the "u_time" field.
func (dpc *DbPackageCreate) SetUTime(i int64) *DbPackageCreate {
	dpc.mutation.SetUTime(i)
	return dpc
}

// SetNillableUTime sets the "u_time" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableUTime(i *int64) *DbPackageCreate {
	if i != nil {
		dpc.SetUTime(*i)
	}
	return dpc
}

// SetSTime sets the "s_time" field.
func (dpc *DbPackageCreate) SetSTime(i int64) *DbPackageCreate {
	dpc.mutation.SetSTime(i)
	return dpc
}

// SetNillableSTime sets the "s_time" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableSTime(i *int64) *DbPackageCreate {
	if i != nil {
		dpc.SetSTime(*i)
	}
	return dpc
}

// SetIoIn sets the "io_in" field.
func (dpc *DbPackageCreate) SetIoIn(i int64) *DbPackageCreate {
	dpc.mutation.SetIoIn(i)
	return dpc
}

// SetNillableIoIn sets the "io_in" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableIoIn(i *int64) *DbPackageCreate {
	if i != nil {
		dpc.SetIoIn(*i)
	}
	return dpc
}

// SetIoOut sets the "io_out" field.
func (dpc *DbPackageCreate) SetIoOut(i int64) *DbPackageCreate {
	dpc.mutation.SetIoOut(i)
	return dpc
}

// SetNillableIoOut sets the "io_out" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableIoOut(i *int64) *DbPackageCreate {
	if i != nil {
		dpc.SetIoOut(*i)
	}
	return dpc
}

// SetSrcinfo sets the "srcinfo" field.
func (dpc *DbPackageCreate) SetSrcinfo(s string) *DbPackageCreate {
	dpc.mutation.SetSrcinfo(s)
	return dpc
}

// SetNillableSrcinfo sets the "srcinfo" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableSrcinfo(s *string) *DbPackageCreate {
	if s != nil {
		dpc.SetSrcinfo(*s)
	}
	return dpc
}

// SetSrcinfoHash sets the "srcinfo_hash" field.
func (dpc *DbPackageCreate) SetSrcinfoHash(s string) *DbPackageCreate {
	dpc.mutation.SetSrcinfoHash(s)
	return dpc
}

// SetNillableSrcinfoHash sets the "srcinfo_hash" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillableSrcinfoHash(s *string) *DbPackageCreate {
	if s != nil {
		dpc.SetSrcinfoHash(*s)
	}
	return dpc
}

// SetPkgbuild sets the "pkgbuild" field.
func (dpc *DbPackageCreate) SetPkgbuild(s string) *DbPackageCreate {
	dpc.mutation.SetPkgbuild(s)
	return dpc
}

// SetNillablePkgbuild sets the "pkgbuild" field if the given value is not nil.
func (dpc *DbPackageCreate) SetNillablePkgbuild(s *string) *DbPackageCreate {
	if s != nil {
		dpc.SetPkgbuild(*s)
	}
	return dpc
}

// Mutation returns the DbPackageMutation object of the builder.
func (dpc *DbPackageCreate) Mutation() *DbPackageMutation {
	return dpc.mutation
}

// Save creates the DbPackage in the database.
func (dpc *DbPackageCreate) Save(ctx context.Context) (*DbPackage, error) {
	var (
		err  error
		node *DbPackage
	)
	dpc.defaults()
	if len(dpc.hooks) == 0 {
		if err = dpc.check(); err != nil {
			return nil, err
		}
		node, err = dpc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DbPackageMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = dpc.check(); err != nil {
				return nil, err
			}
			dpc.mutation = mutation
			if node, err = dpc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(dpc.hooks) - 1; i >= 0; i-- {
			if dpc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = dpc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, dpc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*DbPackage)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from DbPackageMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (dpc *DbPackageCreate) SaveX(ctx context.Context) *DbPackage {
	v, err := dpc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dpc *DbPackageCreate) Exec(ctx context.Context) error {
	_, err := dpc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dpc *DbPackageCreate) ExecX(ctx context.Context) {
	if err := dpc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (dpc *DbPackageCreate) defaults() {
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
func (dpc *DbPackageCreate) check() error {
	if _, ok := dpc.mutation.Pkgbase(); !ok {
		return &ValidationError{Name: "pkgbase", err: errors.New(`ent: missing required field "DbPackage.pkgbase"`)}
	}
	if v, ok := dpc.mutation.Pkgbase(); ok {
		if err := dbpackage.PkgbaseValidator(v); err != nil {
			return &ValidationError{Name: "pkgbase", err: fmt.Errorf(`ent: validator failed for field "DbPackage.pkgbase": %w`, err)}
		}
	}
	if v, ok := dpc.mutation.Status(); ok {
		if err := dbpackage.StatusValidator(v); err != nil {
			return &ValidationError{Name: "status", err: fmt.Errorf(`ent: validator failed for field "DbPackage.status": %w`, err)}
		}
	}
	if _, ok := dpc.mutation.Repository(); !ok {
		return &ValidationError{Name: "repository", err: errors.New(`ent: missing required field "DbPackage.repository"`)}
	}
	if v, ok := dpc.mutation.Repository(); ok {
		if err := dbpackage.RepositoryValidator(v); err != nil {
			return &ValidationError{Name: "repository", err: fmt.Errorf(`ent: validator failed for field "DbPackage.repository": %w`, err)}
		}
	}
	if _, ok := dpc.mutation.March(); !ok {
		return &ValidationError{Name: "march", err: errors.New(`ent: missing required field "DbPackage.march"`)}
	}
	if v, ok := dpc.mutation.March(); ok {
		if err := dbpackage.MarchValidator(v); err != nil {
			return &ValidationError{Name: "march", err: fmt.Errorf(`ent: validator failed for field "DbPackage.march": %w`, err)}
		}
	}
	if v, ok := dpc.mutation.Lto(); ok {
		if err := dbpackage.LtoValidator(v); err != nil {
			return &ValidationError{Name: "lto", err: fmt.Errorf(`ent: validator failed for field "DbPackage.lto": %w`, err)}
		}
	}
	if v, ok := dpc.mutation.DebugSymbols(); ok {
		if err := dbpackage.DebugSymbolsValidator(v); err != nil {
			return &ValidationError{Name: "debug_symbols", err: fmt.Errorf(`ent: validator failed for field "DbPackage.debug_symbols": %w`, err)}
		}
	}
	return nil
}

func (dpc *DbPackageCreate) sqlSave(ctx context.Context) (*DbPackage, error) {
	_node, _spec := dpc.createSpec()
	if err := sqlgraph.CreateNode(ctx, dpc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (dpc *DbPackageCreate) createSpec() (*DbPackage, *sqlgraph.CreateSpec) {
	var (
		_node = &DbPackage{config: dpc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: dbpackage.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: dbpackage.FieldID,
			},
		}
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
	if value, ok := dpc.mutation.Hash(); ok {
		_spec.SetField(dbpackage.FieldHash, field.TypeString, value)
		_node.Hash = value
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
	if value, ok := dpc.mutation.Srcinfo(); ok {
		_spec.SetField(dbpackage.FieldSrcinfo, field.TypeString, value)
		_node.Srcinfo = &value
	}
	if value, ok := dpc.mutation.SrcinfoHash(); ok {
		_spec.SetField(dbpackage.FieldSrcinfoHash, field.TypeString, value)
		_node.SrcinfoHash = value
	}
	if value, ok := dpc.mutation.Pkgbuild(); ok {
		_spec.SetField(dbpackage.FieldPkgbuild, field.TypeString, value)
		_node.Pkgbuild = value
	}
	return _node, _spec
}

// DbPackageCreateBulk is the builder for creating many DbPackage entities in bulk.
type DbPackageCreateBulk struct {
	config
	builders []*DbPackageCreate
}

// Save creates the DbPackage entities in the database.
func (dpcb *DbPackageCreateBulk) Save(ctx context.Context) ([]*DbPackage, error) {
	specs := make([]*sqlgraph.CreateSpec, len(dpcb.builders))
	nodes := make([]*DbPackage, len(dpcb.builders))
	mutators := make([]Mutator, len(dpcb.builders))
	for i := range dpcb.builders {
		func(i int, root context.Context) {
			builder := dpcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*DbPackageMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
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
func (dpcb *DbPackageCreateBulk) SaveX(ctx context.Context) []*DbPackage {
	v, err := dpcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dpcb *DbPackageCreateBulk) Exec(ctx context.Context) error {
	_, err := dpcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dpcb *DbPackageCreateBulk) ExecX(ctx context.Context) {
	if err := dpcb.Exec(ctx); err != nil {
		panic(err)
	}
}
