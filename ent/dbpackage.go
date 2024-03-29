// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
)

// DBPackage is the model entity for the DBPackage schema.
type DBPackage struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// Pkgbase holds the value of the "pkgbase" field.
	Pkgbase string `json:"pkgbase,omitempty"`
	// Packages holds the value of the "packages" field.
	Packages []string `json:"packages,omitempty"`
	// Status holds the value of the "status" field.
	Status dbpackage.Status `json:"status,omitempty"`
	// SkipReason holds the value of the "skip_reason" field.
	SkipReason string `json:"skip_reason,omitempty"`
	// Repository holds the value of the "repository" field.
	Repository dbpackage.Repository `json:"repository,omitempty"`
	// March holds the value of the "march" field.
	March string `json:"march,omitempty"`
	// Version holds the value of the "version" field.
	Version string `json:"version,omitempty"`
	// RepoVersion holds the value of the "repo_version" field.
	RepoVersion string `json:"repo_version,omitempty"`
	// BuildTimeStart holds the value of the "build_time_start" field.
	BuildTimeStart time.Time `json:"build_time_start,omitempty"`
	// Updated holds the value of the "updated" field.
	Updated time.Time `json:"updated,omitempty"`
	// Lto holds the value of the "lto" field.
	Lto dbpackage.Lto `json:"lto,omitempty"`
	// LastVersionBuild holds the value of the "last_version_build" field.
	LastVersionBuild string `json:"last_version_build,omitempty"`
	// LastVerified holds the value of the "last_verified" field.
	LastVerified time.Time `json:"last_verified,omitempty"`
	// DebugSymbols holds the value of the "debug_symbols" field.
	DebugSymbols dbpackage.DebugSymbols `json:"debug_symbols,omitempty"`
	// MaxRss holds the value of the "max_rss" field.
	MaxRss *int64 `json:"max_rss,omitempty"`
	// UTime holds the value of the "u_time" field.
	UTime *int64 `json:"u_time,omitempty"`
	// STime holds the value of the "s_time" field.
	STime *int64 `json:"s_time,omitempty"`
	// IoIn holds the value of the "io_in" field.
	IoIn *int64 `json:"io_in,omitempty"`
	// IoOut holds the value of the "io_out" field.
	IoOut *int64 `json:"io_out,omitempty"`
	// TagRev holds the value of the "tag_rev" field.
	TagRev       *string `json:"tag_rev,omitempty"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*DBPackage) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case dbpackage.FieldPackages:
			values[i] = new([]byte)
		case dbpackage.FieldID, dbpackage.FieldMaxRss, dbpackage.FieldUTime, dbpackage.FieldSTime, dbpackage.FieldIoIn, dbpackage.FieldIoOut:
			values[i] = new(sql.NullInt64)
		case dbpackage.FieldPkgbase, dbpackage.FieldStatus, dbpackage.FieldSkipReason, dbpackage.FieldRepository, dbpackage.FieldMarch, dbpackage.FieldVersion, dbpackage.FieldRepoVersion, dbpackage.FieldLto, dbpackage.FieldLastVersionBuild, dbpackage.FieldDebugSymbols, dbpackage.FieldTagRev:
			values[i] = new(sql.NullString)
		case dbpackage.FieldBuildTimeStart, dbpackage.FieldUpdated, dbpackage.FieldLastVerified:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the DBPackage fields.
func (dp *DBPackage) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case dbpackage.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			dp.ID = int(value.Int64)
		case dbpackage.FieldPkgbase:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field pkgbase", values[i])
			} else if value.Valid {
				dp.Pkgbase = value.String
			}
		case dbpackage.FieldPackages:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field packages", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &dp.Packages); err != nil {
					return fmt.Errorf("unmarshal field packages: %w", err)
				}
			}
		case dbpackage.FieldStatus:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field status", values[i])
			} else if value.Valid {
				dp.Status = dbpackage.Status(value.String)
			}
		case dbpackage.FieldSkipReason:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field skip_reason", values[i])
			} else if value.Valid {
				dp.SkipReason = value.String
			}
		case dbpackage.FieldRepository:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field repository", values[i])
			} else if value.Valid {
				dp.Repository = dbpackage.Repository(value.String)
			}
		case dbpackage.FieldMarch:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field march", values[i])
			} else if value.Valid {
				dp.March = value.String
			}
		case dbpackage.FieldVersion:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field version", values[i])
			} else if value.Valid {
				dp.Version = value.String
			}
		case dbpackage.FieldRepoVersion:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field repo_version", values[i])
			} else if value.Valid {
				dp.RepoVersion = value.String
			}
		case dbpackage.FieldBuildTimeStart:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field build_time_start", values[i])
			} else if value.Valid {
				dp.BuildTimeStart = value.Time
			}
		case dbpackage.FieldUpdated:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated", values[i])
			} else if value.Valid {
				dp.Updated = value.Time
			}
		case dbpackage.FieldLto:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field lto", values[i])
			} else if value.Valid {
				dp.Lto = dbpackage.Lto(value.String)
			}
		case dbpackage.FieldLastVersionBuild:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field last_version_build", values[i])
			} else if value.Valid {
				dp.LastVersionBuild = value.String
			}
		case dbpackage.FieldLastVerified:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field last_verified", values[i])
			} else if value.Valid {
				dp.LastVerified = value.Time
			}
		case dbpackage.FieldDebugSymbols:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field debug_symbols", values[i])
			} else if value.Valid {
				dp.DebugSymbols = dbpackage.DebugSymbols(value.String)
			}
		case dbpackage.FieldMaxRss:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field max_rss", values[i])
			} else if value.Valid {
				dp.MaxRss = new(int64)
				*dp.MaxRss = value.Int64
			}
		case dbpackage.FieldUTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field u_time", values[i])
			} else if value.Valid {
				dp.UTime = new(int64)
				*dp.UTime = value.Int64
			}
		case dbpackage.FieldSTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field s_time", values[i])
			} else if value.Valid {
				dp.STime = new(int64)
				*dp.STime = value.Int64
			}
		case dbpackage.FieldIoIn:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field io_in", values[i])
			} else if value.Valid {
				dp.IoIn = new(int64)
				*dp.IoIn = value.Int64
			}
		case dbpackage.FieldIoOut:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field io_out", values[i])
			} else if value.Valid {
				dp.IoOut = new(int64)
				*dp.IoOut = value.Int64
			}
		case dbpackage.FieldTagRev:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field tag_rev", values[i])
			} else if value.Valid {
				dp.TagRev = new(string)
				*dp.TagRev = value.String
			}
		default:
			dp.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the DBPackage.
// This includes values selected through modifiers, order, etc.
func (dp *DBPackage) Value(name string) (ent.Value, error) {
	return dp.selectValues.Get(name)
}

// Update returns a builder for updating this DBPackage.
// Note that you need to call DBPackage.Unwrap() before calling this method if this DBPackage
// was returned from a transaction, and the transaction was committed or rolled back.
func (dp *DBPackage) Update() *DBPackageUpdateOne {
	return NewDBPackageClient(dp.config).UpdateOne(dp)
}

// Unwrap unwraps the DBPackage entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (dp *DBPackage) Unwrap() *DBPackage {
	_tx, ok := dp.config.driver.(*txDriver)
	if !ok {
		panic("ent: DBPackage is not a transactional entity")
	}
	dp.config.driver = _tx.drv
	return dp
}

// String implements the fmt.Stringer.
func (dp *DBPackage) String() string {
	var builder strings.Builder
	builder.WriteString("DBPackage(")
	builder.WriteString(fmt.Sprintf("id=%v, ", dp.ID))
	builder.WriteString("pkgbase=")
	builder.WriteString(dp.Pkgbase)
	builder.WriteString(", ")
	builder.WriteString("packages=")
	builder.WriteString(fmt.Sprintf("%v", dp.Packages))
	builder.WriteString(", ")
	builder.WriteString("status=")
	builder.WriteString(fmt.Sprintf("%v", dp.Status))
	builder.WriteString(", ")
	builder.WriteString("skip_reason=")
	builder.WriteString(dp.SkipReason)
	builder.WriteString(", ")
	builder.WriteString("repository=")
	builder.WriteString(fmt.Sprintf("%v", dp.Repository))
	builder.WriteString(", ")
	builder.WriteString("march=")
	builder.WriteString(dp.March)
	builder.WriteString(", ")
	builder.WriteString("version=")
	builder.WriteString(dp.Version)
	builder.WriteString(", ")
	builder.WriteString("repo_version=")
	builder.WriteString(dp.RepoVersion)
	builder.WriteString(", ")
	builder.WriteString("build_time_start=")
	builder.WriteString(dp.BuildTimeStart.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated=")
	builder.WriteString(dp.Updated.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("lto=")
	builder.WriteString(fmt.Sprintf("%v", dp.Lto))
	builder.WriteString(", ")
	builder.WriteString("last_version_build=")
	builder.WriteString(dp.LastVersionBuild)
	builder.WriteString(", ")
	builder.WriteString("last_verified=")
	builder.WriteString(dp.LastVerified.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("debug_symbols=")
	builder.WriteString(fmt.Sprintf("%v", dp.DebugSymbols))
	builder.WriteString(", ")
	if v := dp.MaxRss; v != nil {
		builder.WriteString("max_rss=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := dp.UTime; v != nil {
		builder.WriteString("u_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := dp.STime; v != nil {
		builder.WriteString("s_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := dp.IoIn; v != nil {
		builder.WriteString("io_in=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := dp.IoOut; v != nil {
		builder.WriteString("io_out=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := dp.TagRev; v != nil {
		builder.WriteString("tag_rev=")
		builder.WriteString(*v)
	}
	builder.WriteByte(')')
	return builder.String()
}

// DBPackages is a parsable slice of DBPackage.
type DBPackages []*DBPackage
