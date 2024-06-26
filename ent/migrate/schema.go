// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// DbPackagesColumns holds the columns for the "db_packages" table.
	DbPackagesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "pkgbase", Type: field.TypeString},
		{Name: "packages", Type: field.TypeJSON, Nullable: true},
		{Name: "status", Type: field.TypeEnum, Nullable: true, Enums: []string{"skipped", "failed", "built", "queued", "delayed", "building", "latest", "signing", "unknown"}, Default: "unknown"},
		{Name: "skip_reason", Type: field.TypeString, Nullable: true},
		{Name: "repository", Type: field.TypeEnum, Enums: []string{"extra", "core", "multilib"}},
		{Name: "march", Type: field.TypeString},
		{Name: "version", Type: field.TypeString, Nullable: true},
		{Name: "repo_version", Type: field.TypeString, Nullable: true},
		{Name: "build_time_start", Type: field.TypeTime, Nullable: true},
		{Name: "updated", Type: field.TypeTime, Nullable: true},
		{Name: "lto", Type: field.TypeEnum, Nullable: true, Enums: []string{"enabled", "unknown", "disabled", "auto_disabled"}, Default: "unknown"},
		{Name: "last_version_build", Type: field.TypeString, Nullable: true},
		{Name: "last_verified", Type: field.TypeTime, Nullable: true},
		{Name: "debug_symbols", Type: field.TypeEnum, Nullable: true, Enums: []string{"available", "unknown", "not_available"}, Default: "unknown"},
		{Name: "max_rss", Type: field.TypeInt64, Nullable: true},
		{Name: "u_time", Type: field.TypeInt64, Nullable: true},
		{Name: "s_time", Type: field.TypeInt64, Nullable: true},
		{Name: "io_in", Type: field.TypeInt64, Nullable: true},
		{Name: "io_out", Type: field.TypeInt64, Nullable: true},
		{Name: "tag_rev", Type: field.TypeString, Nullable: true},
	}
	// DbPackagesTable holds the schema information for the "db_packages" table.
	DbPackagesTable = &schema.Table{
		Name:       "db_packages",
		Columns:    DbPackagesColumns,
		PrimaryKey: []*schema.Column{DbPackagesColumns[0]},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		DbPackagesTable,
	}
)

func init() {
}
