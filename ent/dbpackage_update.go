// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"somegit.dev/ALHP/ALHP.GO/ent/predicate"
)

// DBPackageUpdate is the builder for updating DBPackage entities.
type DBPackageUpdate struct {
	config
	hooks     []Hook
	mutation  *DBPackageMutation
	modifiers []func(*sql.UpdateBuilder)
}

// Where appends a list predicates to the DBPackageUpdate builder.
func (dpu *DBPackageUpdate) Where(ps ...predicate.DBPackage) *DBPackageUpdate {
	dpu.mutation.Where(ps...)
	return dpu
}

// SetPackages sets the "packages" field.
func (dpu *DBPackageUpdate) SetPackages(s []string) *DBPackageUpdate {
	dpu.mutation.SetPackages(s)
	return dpu
}

// AppendPackages appends s to the "packages" field.
func (dpu *DBPackageUpdate) AppendPackages(s []string) *DBPackageUpdate {
	dpu.mutation.AppendPackages(s)
	return dpu
}

// ClearPackages clears the value of the "packages" field.
func (dpu *DBPackageUpdate) ClearPackages() *DBPackageUpdate {
	dpu.mutation.ClearPackages()
	return dpu
}

// SetStatus sets the "status" field.
func (dpu *DBPackageUpdate) SetStatus(d dbpackage.Status) *DBPackageUpdate {
	dpu.mutation.SetStatus(d)
	return dpu
}

// SetNillableStatus sets the "status" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableStatus(d *dbpackage.Status) *DBPackageUpdate {
	if d != nil {
		dpu.SetStatus(*d)
	}
	return dpu
}

// ClearStatus clears the value of the "status" field.
func (dpu *DBPackageUpdate) ClearStatus() *DBPackageUpdate {
	dpu.mutation.ClearStatus()
	return dpu
}

// SetSkipReason sets the "skip_reason" field.
func (dpu *DBPackageUpdate) SetSkipReason(s string) *DBPackageUpdate {
	dpu.mutation.SetSkipReason(s)
	return dpu
}

// SetNillableSkipReason sets the "skip_reason" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableSkipReason(s *string) *DBPackageUpdate {
	if s != nil {
		dpu.SetSkipReason(*s)
	}
	return dpu
}

// ClearSkipReason clears the value of the "skip_reason" field.
func (dpu *DBPackageUpdate) ClearSkipReason() *DBPackageUpdate {
	dpu.mutation.ClearSkipReason()
	return dpu
}

// SetRepository sets the "repository" field.
func (dpu *DBPackageUpdate) SetRepository(d dbpackage.Repository) *DBPackageUpdate {
	dpu.mutation.SetRepository(d)
	return dpu
}

// SetVersion sets the "version" field.
func (dpu *DBPackageUpdate) SetVersion(s string) *DBPackageUpdate {
	dpu.mutation.SetVersion(s)
	return dpu
}

// SetNillableVersion sets the "version" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableVersion(s *string) *DBPackageUpdate {
	if s != nil {
		dpu.SetVersion(*s)
	}
	return dpu
}

// ClearVersion clears the value of the "version" field.
func (dpu *DBPackageUpdate) ClearVersion() *DBPackageUpdate {
	dpu.mutation.ClearVersion()
	return dpu
}

// SetRepoVersion sets the "repo_version" field.
func (dpu *DBPackageUpdate) SetRepoVersion(s string) *DBPackageUpdate {
	dpu.mutation.SetRepoVersion(s)
	return dpu
}

// SetNillableRepoVersion sets the "repo_version" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableRepoVersion(s *string) *DBPackageUpdate {
	if s != nil {
		dpu.SetRepoVersion(*s)
	}
	return dpu
}

// ClearRepoVersion clears the value of the "repo_version" field.
func (dpu *DBPackageUpdate) ClearRepoVersion() *DBPackageUpdate {
	dpu.mutation.ClearRepoVersion()
	return dpu
}

// SetBuildTimeStart sets the "build_time_start" field.
func (dpu *DBPackageUpdate) SetBuildTimeStart(t time.Time) *DBPackageUpdate {
	dpu.mutation.SetBuildTimeStart(t)
	return dpu
}

// SetNillableBuildTimeStart sets the "build_time_start" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableBuildTimeStart(t *time.Time) *DBPackageUpdate {
	if t != nil {
		dpu.SetBuildTimeStart(*t)
	}
	return dpu
}

// ClearBuildTimeStart clears the value of the "build_time_start" field.
func (dpu *DBPackageUpdate) ClearBuildTimeStart() *DBPackageUpdate {
	dpu.mutation.ClearBuildTimeStart()
	return dpu
}

// SetUpdated sets the "updated" field.
func (dpu *DBPackageUpdate) SetUpdated(t time.Time) *DBPackageUpdate {
	dpu.mutation.SetUpdated(t)
	return dpu
}

// SetNillableUpdated sets the "updated" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableUpdated(t *time.Time) *DBPackageUpdate {
	if t != nil {
		dpu.SetUpdated(*t)
	}
	return dpu
}

// ClearUpdated clears the value of the "updated" field.
func (dpu *DBPackageUpdate) ClearUpdated() *DBPackageUpdate {
	dpu.mutation.ClearUpdated()
	return dpu
}

// SetLto sets the "lto" field.
func (dpu *DBPackageUpdate) SetLto(d dbpackage.Lto) *DBPackageUpdate {
	dpu.mutation.SetLto(d)
	return dpu
}

// SetNillableLto sets the "lto" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableLto(d *dbpackage.Lto) *DBPackageUpdate {
	if d != nil {
		dpu.SetLto(*d)
	}
	return dpu
}

// ClearLto clears the value of the "lto" field.
func (dpu *DBPackageUpdate) ClearLto() *DBPackageUpdate {
	dpu.mutation.ClearLto()
	return dpu
}

// SetLastVersionBuild sets the "last_version_build" field.
func (dpu *DBPackageUpdate) SetLastVersionBuild(s string) *DBPackageUpdate {
	dpu.mutation.SetLastVersionBuild(s)
	return dpu
}

// SetNillableLastVersionBuild sets the "last_version_build" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableLastVersionBuild(s *string) *DBPackageUpdate {
	if s != nil {
		dpu.SetLastVersionBuild(*s)
	}
	return dpu
}

// ClearLastVersionBuild clears the value of the "last_version_build" field.
func (dpu *DBPackageUpdate) ClearLastVersionBuild() *DBPackageUpdate {
	dpu.mutation.ClearLastVersionBuild()
	return dpu
}

// SetLastVerified sets the "last_verified" field.
func (dpu *DBPackageUpdate) SetLastVerified(t time.Time) *DBPackageUpdate {
	dpu.mutation.SetLastVerified(t)
	return dpu
}

// SetNillableLastVerified sets the "last_verified" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableLastVerified(t *time.Time) *DBPackageUpdate {
	if t != nil {
		dpu.SetLastVerified(*t)
	}
	return dpu
}

// ClearLastVerified clears the value of the "last_verified" field.
func (dpu *DBPackageUpdate) ClearLastVerified() *DBPackageUpdate {
	dpu.mutation.ClearLastVerified()
	return dpu
}

// SetDebugSymbols sets the "debug_symbols" field.
func (dpu *DBPackageUpdate) SetDebugSymbols(ds dbpackage.DebugSymbols) *DBPackageUpdate {
	dpu.mutation.SetDebugSymbols(ds)
	return dpu
}

// SetNillableDebugSymbols sets the "debug_symbols" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableDebugSymbols(ds *dbpackage.DebugSymbols) *DBPackageUpdate {
	if ds != nil {
		dpu.SetDebugSymbols(*ds)
	}
	return dpu
}

// ClearDebugSymbols clears the value of the "debug_symbols" field.
func (dpu *DBPackageUpdate) ClearDebugSymbols() *DBPackageUpdate {
	dpu.mutation.ClearDebugSymbols()
	return dpu
}

// SetMaxRss sets the "max_rss" field.
func (dpu *DBPackageUpdate) SetMaxRss(i int64) *DBPackageUpdate {
	dpu.mutation.ResetMaxRss()
	dpu.mutation.SetMaxRss(i)
	return dpu
}

// SetNillableMaxRss sets the "max_rss" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableMaxRss(i *int64) *DBPackageUpdate {
	if i != nil {
		dpu.SetMaxRss(*i)
	}
	return dpu
}

// AddMaxRss adds i to the "max_rss" field.
func (dpu *DBPackageUpdate) AddMaxRss(i int64) *DBPackageUpdate {
	dpu.mutation.AddMaxRss(i)
	return dpu
}

// ClearMaxRss clears the value of the "max_rss" field.
func (dpu *DBPackageUpdate) ClearMaxRss() *DBPackageUpdate {
	dpu.mutation.ClearMaxRss()
	return dpu
}

// SetUTime sets the "u_time" field.
func (dpu *DBPackageUpdate) SetUTime(i int64) *DBPackageUpdate {
	dpu.mutation.ResetUTime()
	dpu.mutation.SetUTime(i)
	return dpu
}

// SetNillableUTime sets the "u_time" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableUTime(i *int64) *DBPackageUpdate {
	if i != nil {
		dpu.SetUTime(*i)
	}
	return dpu
}

// AddUTime adds i to the "u_time" field.
func (dpu *DBPackageUpdate) AddUTime(i int64) *DBPackageUpdate {
	dpu.mutation.AddUTime(i)
	return dpu
}

// ClearUTime clears the value of the "u_time" field.
func (dpu *DBPackageUpdate) ClearUTime() *DBPackageUpdate {
	dpu.mutation.ClearUTime()
	return dpu
}

// SetSTime sets the "s_time" field.
func (dpu *DBPackageUpdate) SetSTime(i int64) *DBPackageUpdate {
	dpu.mutation.ResetSTime()
	dpu.mutation.SetSTime(i)
	return dpu
}

// SetNillableSTime sets the "s_time" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableSTime(i *int64) *DBPackageUpdate {
	if i != nil {
		dpu.SetSTime(*i)
	}
	return dpu
}

// AddSTime adds i to the "s_time" field.
func (dpu *DBPackageUpdate) AddSTime(i int64) *DBPackageUpdate {
	dpu.mutation.AddSTime(i)
	return dpu
}

// ClearSTime clears the value of the "s_time" field.
func (dpu *DBPackageUpdate) ClearSTime() *DBPackageUpdate {
	dpu.mutation.ClearSTime()
	return dpu
}

// SetIoIn sets the "io_in" field.
func (dpu *DBPackageUpdate) SetIoIn(i int64) *DBPackageUpdate {
	dpu.mutation.ResetIoIn()
	dpu.mutation.SetIoIn(i)
	return dpu
}

// SetNillableIoIn sets the "io_in" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableIoIn(i *int64) *DBPackageUpdate {
	if i != nil {
		dpu.SetIoIn(*i)
	}
	return dpu
}

// AddIoIn adds i to the "io_in" field.
func (dpu *DBPackageUpdate) AddIoIn(i int64) *DBPackageUpdate {
	dpu.mutation.AddIoIn(i)
	return dpu
}

// ClearIoIn clears the value of the "io_in" field.
func (dpu *DBPackageUpdate) ClearIoIn() *DBPackageUpdate {
	dpu.mutation.ClearIoIn()
	return dpu
}

// SetIoOut sets the "io_out" field.
func (dpu *DBPackageUpdate) SetIoOut(i int64) *DBPackageUpdate {
	dpu.mutation.ResetIoOut()
	dpu.mutation.SetIoOut(i)
	return dpu
}

// SetNillableIoOut sets the "io_out" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableIoOut(i *int64) *DBPackageUpdate {
	if i != nil {
		dpu.SetIoOut(*i)
	}
	return dpu
}

// AddIoOut adds i to the "io_out" field.
func (dpu *DBPackageUpdate) AddIoOut(i int64) *DBPackageUpdate {
	dpu.mutation.AddIoOut(i)
	return dpu
}

// ClearIoOut clears the value of the "io_out" field.
func (dpu *DBPackageUpdate) ClearIoOut() *DBPackageUpdate {
	dpu.mutation.ClearIoOut()
	return dpu
}

// SetTagRev sets the "tag_rev" field.
func (dpu *DBPackageUpdate) SetTagRev(s string) *DBPackageUpdate {
	dpu.mutation.SetTagRev(s)
	return dpu
}

// SetNillableTagRev sets the "tag_rev" field if the given value is not nil.
func (dpu *DBPackageUpdate) SetNillableTagRev(s *string) *DBPackageUpdate {
	if s != nil {
		dpu.SetTagRev(*s)
	}
	return dpu
}

// ClearTagRev clears the value of the "tag_rev" field.
func (dpu *DBPackageUpdate) ClearTagRev() *DBPackageUpdate {
	dpu.mutation.ClearTagRev()
	return dpu
}

// Mutation returns the DBPackageMutation object of the builder.
func (dpu *DBPackageUpdate) Mutation() *DBPackageMutation {
	return dpu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (dpu *DBPackageUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, dpu.sqlSave, dpu.mutation, dpu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (dpu *DBPackageUpdate) SaveX(ctx context.Context) int {
	affected, err := dpu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (dpu *DBPackageUpdate) Exec(ctx context.Context) error {
	_, err := dpu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dpu *DBPackageUpdate) ExecX(ctx context.Context) {
	if err := dpu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (dpu *DBPackageUpdate) check() error {
	if v, ok := dpu.mutation.Status(); ok {
		if err := dbpackage.StatusValidator(v); err != nil {
			return &ValidationError{Name: "status", err: fmt.Errorf(`ent: validator failed for field "DBPackage.status": %w`, err)}
		}
	}
	if v, ok := dpu.mutation.Repository(); ok {
		if err := dbpackage.RepositoryValidator(v); err != nil {
			return &ValidationError{Name: "repository", err: fmt.Errorf(`ent: validator failed for field "DBPackage.repository": %w`, err)}
		}
	}
	if v, ok := dpu.mutation.Lto(); ok {
		if err := dbpackage.LtoValidator(v); err != nil {
			return &ValidationError{Name: "lto", err: fmt.Errorf(`ent: validator failed for field "DBPackage.lto": %w`, err)}
		}
	}
	if v, ok := dpu.mutation.DebugSymbols(); ok {
		if err := dbpackage.DebugSymbolsValidator(v); err != nil {
			return &ValidationError{Name: "debug_symbols", err: fmt.Errorf(`ent: validator failed for field "DBPackage.debug_symbols": %w`, err)}
		}
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (dpu *DBPackageUpdate) Modify(modifiers ...func(u *sql.UpdateBuilder)) *DBPackageUpdate {
	dpu.modifiers = append(dpu.modifiers, modifiers...)
	return dpu
}

func (dpu *DBPackageUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := dpu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(dbpackage.Table, dbpackage.Columns, sqlgraph.NewFieldSpec(dbpackage.FieldID, field.TypeInt))
	if ps := dpu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := dpu.mutation.Packages(); ok {
		_spec.SetField(dbpackage.FieldPackages, field.TypeJSON, value)
	}
	if value, ok := dpu.mutation.AppendedPackages(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, dbpackage.FieldPackages, value)
		})
	}
	if dpu.mutation.PackagesCleared() {
		_spec.ClearField(dbpackage.FieldPackages, field.TypeJSON)
	}
	if value, ok := dpu.mutation.Status(); ok {
		_spec.SetField(dbpackage.FieldStatus, field.TypeEnum, value)
	}
	if dpu.mutation.StatusCleared() {
		_spec.ClearField(dbpackage.FieldStatus, field.TypeEnum)
	}
	if value, ok := dpu.mutation.SkipReason(); ok {
		_spec.SetField(dbpackage.FieldSkipReason, field.TypeString, value)
	}
	if dpu.mutation.SkipReasonCleared() {
		_spec.ClearField(dbpackage.FieldSkipReason, field.TypeString)
	}
	if value, ok := dpu.mutation.Repository(); ok {
		_spec.SetField(dbpackage.FieldRepository, field.TypeEnum, value)
	}
	if value, ok := dpu.mutation.Version(); ok {
		_spec.SetField(dbpackage.FieldVersion, field.TypeString, value)
	}
	if dpu.mutation.VersionCleared() {
		_spec.ClearField(dbpackage.FieldVersion, field.TypeString)
	}
	if value, ok := dpu.mutation.RepoVersion(); ok {
		_spec.SetField(dbpackage.FieldRepoVersion, field.TypeString, value)
	}
	if dpu.mutation.RepoVersionCleared() {
		_spec.ClearField(dbpackage.FieldRepoVersion, field.TypeString)
	}
	if value, ok := dpu.mutation.BuildTimeStart(); ok {
		_spec.SetField(dbpackage.FieldBuildTimeStart, field.TypeTime, value)
	}
	if dpu.mutation.BuildTimeStartCleared() {
		_spec.ClearField(dbpackage.FieldBuildTimeStart, field.TypeTime)
	}
	if value, ok := dpu.mutation.Updated(); ok {
		_spec.SetField(dbpackage.FieldUpdated, field.TypeTime, value)
	}
	if dpu.mutation.UpdatedCleared() {
		_spec.ClearField(dbpackage.FieldUpdated, field.TypeTime)
	}
	if value, ok := dpu.mutation.Lto(); ok {
		_spec.SetField(dbpackage.FieldLto, field.TypeEnum, value)
	}
	if dpu.mutation.LtoCleared() {
		_spec.ClearField(dbpackage.FieldLto, field.TypeEnum)
	}
	if value, ok := dpu.mutation.LastVersionBuild(); ok {
		_spec.SetField(dbpackage.FieldLastVersionBuild, field.TypeString, value)
	}
	if dpu.mutation.LastVersionBuildCleared() {
		_spec.ClearField(dbpackage.FieldLastVersionBuild, field.TypeString)
	}
	if value, ok := dpu.mutation.LastVerified(); ok {
		_spec.SetField(dbpackage.FieldLastVerified, field.TypeTime, value)
	}
	if dpu.mutation.LastVerifiedCleared() {
		_spec.ClearField(dbpackage.FieldLastVerified, field.TypeTime)
	}
	if value, ok := dpu.mutation.DebugSymbols(); ok {
		_spec.SetField(dbpackage.FieldDebugSymbols, field.TypeEnum, value)
	}
	if dpu.mutation.DebugSymbolsCleared() {
		_spec.ClearField(dbpackage.FieldDebugSymbols, field.TypeEnum)
	}
	if value, ok := dpu.mutation.MaxRss(); ok {
		_spec.SetField(dbpackage.FieldMaxRss, field.TypeInt64, value)
	}
	if value, ok := dpu.mutation.AddedMaxRss(); ok {
		_spec.AddField(dbpackage.FieldMaxRss, field.TypeInt64, value)
	}
	if dpu.mutation.MaxRssCleared() {
		_spec.ClearField(dbpackage.FieldMaxRss, field.TypeInt64)
	}
	if value, ok := dpu.mutation.UTime(); ok {
		_spec.SetField(dbpackage.FieldUTime, field.TypeInt64, value)
	}
	if value, ok := dpu.mutation.AddedUTime(); ok {
		_spec.AddField(dbpackage.FieldUTime, field.TypeInt64, value)
	}
	if dpu.mutation.UTimeCleared() {
		_spec.ClearField(dbpackage.FieldUTime, field.TypeInt64)
	}
	if value, ok := dpu.mutation.STime(); ok {
		_spec.SetField(dbpackage.FieldSTime, field.TypeInt64, value)
	}
	if value, ok := dpu.mutation.AddedSTime(); ok {
		_spec.AddField(dbpackage.FieldSTime, field.TypeInt64, value)
	}
	if dpu.mutation.STimeCleared() {
		_spec.ClearField(dbpackage.FieldSTime, field.TypeInt64)
	}
	if value, ok := dpu.mutation.IoIn(); ok {
		_spec.SetField(dbpackage.FieldIoIn, field.TypeInt64, value)
	}
	if value, ok := dpu.mutation.AddedIoIn(); ok {
		_spec.AddField(dbpackage.FieldIoIn, field.TypeInt64, value)
	}
	if dpu.mutation.IoInCleared() {
		_spec.ClearField(dbpackage.FieldIoIn, field.TypeInt64)
	}
	if value, ok := dpu.mutation.IoOut(); ok {
		_spec.SetField(dbpackage.FieldIoOut, field.TypeInt64, value)
	}
	if value, ok := dpu.mutation.AddedIoOut(); ok {
		_spec.AddField(dbpackage.FieldIoOut, field.TypeInt64, value)
	}
	if dpu.mutation.IoOutCleared() {
		_spec.ClearField(dbpackage.FieldIoOut, field.TypeInt64)
	}
	if value, ok := dpu.mutation.TagRev(); ok {
		_spec.SetField(dbpackage.FieldTagRev, field.TypeString, value)
	}
	if dpu.mutation.TagRevCleared() {
		_spec.ClearField(dbpackage.FieldTagRev, field.TypeString)
	}
	_spec.AddModifiers(dpu.modifiers...)
	if n, err = sqlgraph.UpdateNodes(ctx, dpu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{dbpackage.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	dpu.mutation.done = true
	return n, nil
}

// DBPackageUpdateOne is the builder for updating a single DBPackage entity.
type DBPackageUpdateOne struct {
	config
	fields    []string
	hooks     []Hook
	mutation  *DBPackageMutation
	modifiers []func(*sql.UpdateBuilder)
}

// SetPackages sets the "packages" field.
func (dpuo *DBPackageUpdateOne) SetPackages(s []string) *DBPackageUpdateOne {
	dpuo.mutation.SetPackages(s)
	return dpuo
}

// AppendPackages appends s to the "packages" field.
func (dpuo *DBPackageUpdateOne) AppendPackages(s []string) *DBPackageUpdateOne {
	dpuo.mutation.AppendPackages(s)
	return dpuo
}

// ClearPackages clears the value of the "packages" field.
func (dpuo *DBPackageUpdateOne) ClearPackages() *DBPackageUpdateOne {
	dpuo.mutation.ClearPackages()
	return dpuo
}

// SetStatus sets the "status" field.
func (dpuo *DBPackageUpdateOne) SetStatus(d dbpackage.Status) *DBPackageUpdateOne {
	dpuo.mutation.SetStatus(d)
	return dpuo
}

// SetNillableStatus sets the "status" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableStatus(d *dbpackage.Status) *DBPackageUpdateOne {
	if d != nil {
		dpuo.SetStatus(*d)
	}
	return dpuo
}

// ClearStatus clears the value of the "status" field.
func (dpuo *DBPackageUpdateOne) ClearStatus() *DBPackageUpdateOne {
	dpuo.mutation.ClearStatus()
	return dpuo
}

// SetSkipReason sets the "skip_reason" field.
func (dpuo *DBPackageUpdateOne) SetSkipReason(s string) *DBPackageUpdateOne {
	dpuo.mutation.SetSkipReason(s)
	return dpuo
}

// SetNillableSkipReason sets the "skip_reason" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableSkipReason(s *string) *DBPackageUpdateOne {
	if s != nil {
		dpuo.SetSkipReason(*s)
	}
	return dpuo
}

// ClearSkipReason clears the value of the "skip_reason" field.
func (dpuo *DBPackageUpdateOne) ClearSkipReason() *DBPackageUpdateOne {
	dpuo.mutation.ClearSkipReason()
	return dpuo
}

// SetRepository sets the "repository" field.
func (dpuo *DBPackageUpdateOne) SetRepository(d dbpackage.Repository) *DBPackageUpdateOne {
	dpuo.mutation.SetRepository(d)
	return dpuo
}

// SetVersion sets the "version" field.
func (dpuo *DBPackageUpdateOne) SetVersion(s string) *DBPackageUpdateOne {
	dpuo.mutation.SetVersion(s)
	return dpuo
}

// SetNillableVersion sets the "version" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableVersion(s *string) *DBPackageUpdateOne {
	if s != nil {
		dpuo.SetVersion(*s)
	}
	return dpuo
}

// ClearVersion clears the value of the "version" field.
func (dpuo *DBPackageUpdateOne) ClearVersion() *DBPackageUpdateOne {
	dpuo.mutation.ClearVersion()
	return dpuo
}

// SetRepoVersion sets the "repo_version" field.
func (dpuo *DBPackageUpdateOne) SetRepoVersion(s string) *DBPackageUpdateOne {
	dpuo.mutation.SetRepoVersion(s)
	return dpuo
}

// SetNillableRepoVersion sets the "repo_version" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableRepoVersion(s *string) *DBPackageUpdateOne {
	if s != nil {
		dpuo.SetRepoVersion(*s)
	}
	return dpuo
}

// ClearRepoVersion clears the value of the "repo_version" field.
func (dpuo *DBPackageUpdateOne) ClearRepoVersion() *DBPackageUpdateOne {
	dpuo.mutation.ClearRepoVersion()
	return dpuo
}

// SetBuildTimeStart sets the "build_time_start" field.
func (dpuo *DBPackageUpdateOne) SetBuildTimeStart(t time.Time) *DBPackageUpdateOne {
	dpuo.mutation.SetBuildTimeStart(t)
	return dpuo
}

// SetNillableBuildTimeStart sets the "build_time_start" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableBuildTimeStart(t *time.Time) *DBPackageUpdateOne {
	if t != nil {
		dpuo.SetBuildTimeStart(*t)
	}
	return dpuo
}

// ClearBuildTimeStart clears the value of the "build_time_start" field.
func (dpuo *DBPackageUpdateOne) ClearBuildTimeStart() *DBPackageUpdateOne {
	dpuo.mutation.ClearBuildTimeStart()
	return dpuo
}

// SetUpdated sets the "updated" field.
func (dpuo *DBPackageUpdateOne) SetUpdated(t time.Time) *DBPackageUpdateOne {
	dpuo.mutation.SetUpdated(t)
	return dpuo
}

// SetNillableUpdated sets the "updated" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableUpdated(t *time.Time) *DBPackageUpdateOne {
	if t != nil {
		dpuo.SetUpdated(*t)
	}
	return dpuo
}

// ClearUpdated clears the value of the "updated" field.
func (dpuo *DBPackageUpdateOne) ClearUpdated() *DBPackageUpdateOne {
	dpuo.mutation.ClearUpdated()
	return dpuo
}

// SetLto sets the "lto" field.
func (dpuo *DBPackageUpdateOne) SetLto(d dbpackage.Lto) *DBPackageUpdateOne {
	dpuo.mutation.SetLto(d)
	return dpuo
}

// SetNillableLto sets the "lto" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableLto(d *dbpackage.Lto) *DBPackageUpdateOne {
	if d != nil {
		dpuo.SetLto(*d)
	}
	return dpuo
}

// ClearLto clears the value of the "lto" field.
func (dpuo *DBPackageUpdateOne) ClearLto() *DBPackageUpdateOne {
	dpuo.mutation.ClearLto()
	return dpuo
}

// SetLastVersionBuild sets the "last_version_build" field.
func (dpuo *DBPackageUpdateOne) SetLastVersionBuild(s string) *DBPackageUpdateOne {
	dpuo.mutation.SetLastVersionBuild(s)
	return dpuo
}

// SetNillableLastVersionBuild sets the "last_version_build" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableLastVersionBuild(s *string) *DBPackageUpdateOne {
	if s != nil {
		dpuo.SetLastVersionBuild(*s)
	}
	return dpuo
}

// ClearLastVersionBuild clears the value of the "last_version_build" field.
func (dpuo *DBPackageUpdateOne) ClearLastVersionBuild() *DBPackageUpdateOne {
	dpuo.mutation.ClearLastVersionBuild()
	return dpuo
}

// SetLastVerified sets the "last_verified" field.
func (dpuo *DBPackageUpdateOne) SetLastVerified(t time.Time) *DBPackageUpdateOne {
	dpuo.mutation.SetLastVerified(t)
	return dpuo
}

// SetNillableLastVerified sets the "last_verified" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableLastVerified(t *time.Time) *DBPackageUpdateOne {
	if t != nil {
		dpuo.SetLastVerified(*t)
	}
	return dpuo
}

// ClearLastVerified clears the value of the "last_verified" field.
func (dpuo *DBPackageUpdateOne) ClearLastVerified() *DBPackageUpdateOne {
	dpuo.mutation.ClearLastVerified()
	return dpuo
}

// SetDebugSymbols sets the "debug_symbols" field.
func (dpuo *DBPackageUpdateOne) SetDebugSymbols(ds dbpackage.DebugSymbols) *DBPackageUpdateOne {
	dpuo.mutation.SetDebugSymbols(ds)
	return dpuo
}

// SetNillableDebugSymbols sets the "debug_symbols" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableDebugSymbols(ds *dbpackage.DebugSymbols) *DBPackageUpdateOne {
	if ds != nil {
		dpuo.SetDebugSymbols(*ds)
	}
	return dpuo
}

// ClearDebugSymbols clears the value of the "debug_symbols" field.
func (dpuo *DBPackageUpdateOne) ClearDebugSymbols() *DBPackageUpdateOne {
	dpuo.mutation.ClearDebugSymbols()
	return dpuo
}

// SetMaxRss sets the "max_rss" field.
func (dpuo *DBPackageUpdateOne) SetMaxRss(i int64) *DBPackageUpdateOne {
	dpuo.mutation.ResetMaxRss()
	dpuo.mutation.SetMaxRss(i)
	return dpuo
}

// SetNillableMaxRss sets the "max_rss" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableMaxRss(i *int64) *DBPackageUpdateOne {
	if i != nil {
		dpuo.SetMaxRss(*i)
	}
	return dpuo
}

// AddMaxRss adds i to the "max_rss" field.
func (dpuo *DBPackageUpdateOne) AddMaxRss(i int64) *DBPackageUpdateOne {
	dpuo.mutation.AddMaxRss(i)
	return dpuo
}

// ClearMaxRss clears the value of the "max_rss" field.
func (dpuo *DBPackageUpdateOne) ClearMaxRss() *DBPackageUpdateOne {
	dpuo.mutation.ClearMaxRss()
	return dpuo
}

// SetUTime sets the "u_time" field.
func (dpuo *DBPackageUpdateOne) SetUTime(i int64) *DBPackageUpdateOne {
	dpuo.mutation.ResetUTime()
	dpuo.mutation.SetUTime(i)
	return dpuo
}

// SetNillableUTime sets the "u_time" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableUTime(i *int64) *DBPackageUpdateOne {
	if i != nil {
		dpuo.SetUTime(*i)
	}
	return dpuo
}

// AddUTime adds i to the "u_time" field.
func (dpuo *DBPackageUpdateOne) AddUTime(i int64) *DBPackageUpdateOne {
	dpuo.mutation.AddUTime(i)
	return dpuo
}

// ClearUTime clears the value of the "u_time" field.
func (dpuo *DBPackageUpdateOne) ClearUTime() *DBPackageUpdateOne {
	dpuo.mutation.ClearUTime()
	return dpuo
}

// SetSTime sets the "s_time" field.
func (dpuo *DBPackageUpdateOne) SetSTime(i int64) *DBPackageUpdateOne {
	dpuo.mutation.ResetSTime()
	dpuo.mutation.SetSTime(i)
	return dpuo
}

// SetNillableSTime sets the "s_time" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableSTime(i *int64) *DBPackageUpdateOne {
	if i != nil {
		dpuo.SetSTime(*i)
	}
	return dpuo
}

// AddSTime adds i to the "s_time" field.
func (dpuo *DBPackageUpdateOne) AddSTime(i int64) *DBPackageUpdateOne {
	dpuo.mutation.AddSTime(i)
	return dpuo
}

// ClearSTime clears the value of the "s_time" field.
func (dpuo *DBPackageUpdateOne) ClearSTime() *DBPackageUpdateOne {
	dpuo.mutation.ClearSTime()
	return dpuo
}

// SetIoIn sets the "io_in" field.
func (dpuo *DBPackageUpdateOne) SetIoIn(i int64) *DBPackageUpdateOne {
	dpuo.mutation.ResetIoIn()
	dpuo.mutation.SetIoIn(i)
	return dpuo
}

// SetNillableIoIn sets the "io_in" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableIoIn(i *int64) *DBPackageUpdateOne {
	if i != nil {
		dpuo.SetIoIn(*i)
	}
	return dpuo
}

// AddIoIn adds i to the "io_in" field.
func (dpuo *DBPackageUpdateOne) AddIoIn(i int64) *DBPackageUpdateOne {
	dpuo.mutation.AddIoIn(i)
	return dpuo
}

// ClearIoIn clears the value of the "io_in" field.
func (dpuo *DBPackageUpdateOne) ClearIoIn() *DBPackageUpdateOne {
	dpuo.mutation.ClearIoIn()
	return dpuo
}

// SetIoOut sets the "io_out" field.
func (dpuo *DBPackageUpdateOne) SetIoOut(i int64) *DBPackageUpdateOne {
	dpuo.mutation.ResetIoOut()
	dpuo.mutation.SetIoOut(i)
	return dpuo
}

// SetNillableIoOut sets the "io_out" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableIoOut(i *int64) *DBPackageUpdateOne {
	if i != nil {
		dpuo.SetIoOut(*i)
	}
	return dpuo
}

// AddIoOut adds i to the "io_out" field.
func (dpuo *DBPackageUpdateOne) AddIoOut(i int64) *DBPackageUpdateOne {
	dpuo.mutation.AddIoOut(i)
	return dpuo
}

// ClearIoOut clears the value of the "io_out" field.
func (dpuo *DBPackageUpdateOne) ClearIoOut() *DBPackageUpdateOne {
	dpuo.mutation.ClearIoOut()
	return dpuo
}

// SetTagRev sets the "tag_rev" field.
func (dpuo *DBPackageUpdateOne) SetTagRev(s string) *DBPackageUpdateOne {
	dpuo.mutation.SetTagRev(s)
	return dpuo
}

// SetNillableTagRev sets the "tag_rev" field if the given value is not nil.
func (dpuo *DBPackageUpdateOne) SetNillableTagRev(s *string) *DBPackageUpdateOne {
	if s != nil {
		dpuo.SetTagRev(*s)
	}
	return dpuo
}

// ClearTagRev clears the value of the "tag_rev" field.
func (dpuo *DBPackageUpdateOne) ClearTagRev() *DBPackageUpdateOne {
	dpuo.mutation.ClearTagRev()
	return dpuo
}

// Mutation returns the DBPackageMutation object of the builder.
func (dpuo *DBPackageUpdateOne) Mutation() *DBPackageMutation {
	return dpuo.mutation
}

// Where appends a list predicates to the DBPackageUpdate builder.
func (dpuo *DBPackageUpdateOne) Where(ps ...predicate.DBPackage) *DBPackageUpdateOne {
	dpuo.mutation.Where(ps...)
	return dpuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (dpuo *DBPackageUpdateOne) Select(field string, fields ...string) *DBPackageUpdateOne {
	dpuo.fields = append([]string{field}, fields...)
	return dpuo
}

// Save executes the query and returns the updated DBPackage entity.
func (dpuo *DBPackageUpdateOne) Save(ctx context.Context) (*DBPackage, error) {
	return withHooks(ctx, dpuo.sqlSave, dpuo.mutation, dpuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (dpuo *DBPackageUpdateOne) SaveX(ctx context.Context) *DBPackage {
	node, err := dpuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (dpuo *DBPackageUpdateOne) Exec(ctx context.Context) error {
	_, err := dpuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dpuo *DBPackageUpdateOne) ExecX(ctx context.Context) {
	if err := dpuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (dpuo *DBPackageUpdateOne) check() error {
	if v, ok := dpuo.mutation.Status(); ok {
		if err := dbpackage.StatusValidator(v); err != nil {
			return &ValidationError{Name: "status", err: fmt.Errorf(`ent: validator failed for field "DBPackage.status": %w`, err)}
		}
	}
	if v, ok := dpuo.mutation.Repository(); ok {
		if err := dbpackage.RepositoryValidator(v); err != nil {
			return &ValidationError{Name: "repository", err: fmt.Errorf(`ent: validator failed for field "DBPackage.repository": %w`, err)}
		}
	}
	if v, ok := dpuo.mutation.Lto(); ok {
		if err := dbpackage.LtoValidator(v); err != nil {
			return &ValidationError{Name: "lto", err: fmt.Errorf(`ent: validator failed for field "DBPackage.lto": %w`, err)}
		}
	}
	if v, ok := dpuo.mutation.DebugSymbols(); ok {
		if err := dbpackage.DebugSymbolsValidator(v); err != nil {
			return &ValidationError{Name: "debug_symbols", err: fmt.Errorf(`ent: validator failed for field "DBPackage.debug_symbols": %w`, err)}
		}
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (dpuo *DBPackageUpdateOne) Modify(modifiers ...func(u *sql.UpdateBuilder)) *DBPackageUpdateOne {
	dpuo.modifiers = append(dpuo.modifiers, modifiers...)
	return dpuo
}

func (dpuo *DBPackageUpdateOne) sqlSave(ctx context.Context) (_node *DBPackage, err error) {
	if err := dpuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(dbpackage.Table, dbpackage.Columns, sqlgraph.NewFieldSpec(dbpackage.FieldID, field.TypeInt))
	id, ok := dpuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "DBPackage.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := dpuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, dbpackage.FieldID)
		for _, f := range fields {
			if !dbpackage.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != dbpackage.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := dpuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := dpuo.mutation.Packages(); ok {
		_spec.SetField(dbpackage.FieldPackages, field.TypeJSON, value)
	}
	if value, ok := dpuo.mutation.AppendedPackages(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, dbpackage.FieldPackages, value)
		})
	}
	if dpuo.mutation.PackagesCleared() {
		_spec.ClearField(dbpackage.FieldPackages, field.TypeJSON)
	}
	if value, ok := dpuo.mutation.Status(); ok {
		_spec.SetField(dbpackage.FieldStatus, field.TypeEnum, value)
	}
	if dpuo.mutation.StatusCleared() {
		_spec.ClearField(dbpackage.FieldStatus, field.TypeEnum)
	}
	if value, ok := dpuo.mutation.SkipReason(); ok {
		_spec.SetField(dbpackage.FieldSkipReason, field.TypeString, value)
	}
	if dpuo.mutation.SkipReasonCleared() {
		_spec.ClearField(dbpackage.FieldSkipReason, field.TypeString)
	}
	if value, ok := dpuo.mutation.Repository(); ok {
		_spec.SetField(dbpackage.FieldRepository, field.TypeEnum, value)
	}
	if value, ok := dpuo.mutation.Version(); ok {
		_spec.SetField(dbpackage.FieldVersion, field.TypeString, value)
	}
	if dpuo.mutation.VersionCleared() {
		_spec.ClearField(dbpackage.FieldVersion, field.TypeString)
	}
	if value, ok := dpuo.mutation.RepoVersion(); ok {
		_spec.SetField(dbpackage.FieldRepoVersion, field.TypeString, value)
	}
	if dpuo.mutation.RepoVersionCleared() {
		_spec.ClearField(dbpackage.FieldRepoVersion, field.TypeString)
	}
	if value, ok := dpuo.mutation.BuildTimeStart(); ok {
		_spec.SetField(dbpackage.FieldBuildTimeStart, field.TypeTime, value)
	}
	if dpuo.mutation.BuildTimeStartCleared() {
		_spec.ClearField(dbpackage.FieldBuildTimeStart, field.TypeTime)
	}
	if value, ok := dpuo.mutation.Updated(); ok {
		_spec.SetField(dbpackage.FieldUpdated, field.TypeTime, value)
	}
	if dpuo.mutation.UpdatedCleared() {
		_spec.ClearField(dbpackage.FieldUpdated, field.TypeTime)
	}
	if value, ok := dpuo.mutation.Lto(); ok {
		_spec.SetField(dbpackage.FieldLto, field.TypeEnum, value)
	}
	if dpuo.mutation.LtoCleared() {
		_spec.ClearField(dbpackage.FieldLto, field.TypeEnum)
	}
	if value, ok := dpuo.mutation.LastVersionBuild(); ok {
		_spec.SetField(dbpackage.FieldLastVersionBuild, field.TypeString, value)
	}
	if dpuo.mutation.LastVersionBuildCleared() {
		_spec.ClearField(dbpackage.FieldLastVersionBuild, field.TypeString)
	}
	if value, ok := dpuo.mutation.LastVerified(); ok {
		_spec.SetField(dbpackage.FieldLastVerified, field.TypeTime, value)
	}
	if dpuo.mutation.LastVerifiedCleared() {
		_spec.ClearField(dbpackage.FieldLastVerified, field.TypeTime)
	}
	if value, ok := dpuo.mutation.DebugSymbols(); ok {
		_spec.SetField(dbpackage.FieldDebugSymbols, field.TypeEnum, value)
	}
	if dpuo.mutation.DebugSymbolsCleared() {
		_spec.ClearField(dbpackage.FieldDebugSymbols, field.TypeEnum)
	}
	if value, ok := dpuo.mutation.MaxRss(); ok {
		_spec.SetField(dbpackage.FieldMaxRss, field.TypeInt64, value)
	}
	if value, ok := dpuo.mutation.AddedMaxRss(); ok {
		_spec.AddField(dbpackage.FieldMaxRss, field.TypeInt64, value)
	}
	if dpuo.mutation.MaxRssCleared() {
		_spec.ClearField(dbpackage.FieldMaxRss, field.TypeInt64)
	}
	if value, ok := dpuo.mutation.UTime(); ok {
		_spec.SetField(dbpackage.FieldUTime, field.TypeInt64, value)
	}
	if value, ok := dpuo.mutation.AddedUTime(); ok {
		_spec.AddField(dbpackage.FieldUTime, field.TypeInt64, value)
	}
	if dpuo.mutation.UTimeCleared() {
		_spec.ClearField(dbpackage.FieldUTime, field.TypeInt64)
	}
	if value, ok := dpuo.mutation.STime(); ok {
		_spec.SetField(dbpackage.FieldSTime, field.TypeInt64, value)
	}
	if value, ok := dpuo.mutation.AddedSTime(); ok {
		_spec.AddField(dbpackage.FieldSTime, field.TypeInt64, value)
	}
	if dpuo.mutation.STimeCleared() {
		_spec.ClearField(dbpackage.FieldSTime, field.TypeInt64)
	}
	if value, ok := dpuo.mutation.IoIn(); ok {
		_spec.SetField(dbpackage.FieldIoIn, field.TypeInt64, value)
	}
	if value, ok := dpuo.mutation.AddedIoIn(); ok {
		_spec.AddField(dbpackage.FieldIoIn, field.TypeInt64, value)
	}
	if dpuo.mutation.IoInCleared() {
		_spec.ClearField(dbpackage.FieldIoIn, field.TypeInt64)
	}
	if value, ok := dpuo.mutation.IoOut(); ok {
		_spec.SetField(dbpackage.FieldIoOut, field.TypeInt64, value)
	}
	if value, ok := dpuo.mutation.AddedIoOut(); ok {
		_spec.AddField(dbpackage.FieldIoOut, field.TypeInt64, value)
	}
	if dpuo.mutation.IoOutCleared() {
		_spec.ClearField(dbpackage.FieldIoOut, field.TypeInt64)
	}
	if value, ok := dpuo.mutation.TagRev(); ok {
		_spec.SetField(dbpackage.FieldTagRev, field.TypeString, value)
	}
	if dpuo.mutation.TagRevCleared() {
		_spec.ClearField(dbpackage.FieldTagRev, field.TypeString)
	}
	_spec.AddModifiers(dpuo.modifiers...)
	_node = &DBPackage{config: dpuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, dpuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{dbpackage.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	dpuo.mutation.done = true
	return _node, nil
}
