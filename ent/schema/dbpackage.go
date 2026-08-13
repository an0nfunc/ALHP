package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// DBPackage holds the schema definition for the DbPackage entity.
type DBPackage struct {
	ent.Schema
}

// Fields of the DBPackage.
func (DBPackage) Fields() []ent.Field {
	return []ent.Field{
		field.String("pkgbase").NotEmpty().Immutable(),
		field.Strings("packages").Optional(),
		field.Enum("status").Values("skipped", "failed", "built", "queued", "delayed", "building",
			"latest", "signing", "unknown").Default("unknown").Optional(),
		field.String("skip_reason").Optional(),
		field.Enum("repository").Values("extra", "core", "multilib"),
		field.String("march").NotEmpty().Immutable(),
		field.String("version").Optional(),
		field.String("repo_version").Optional(),
		field.Time("build_time_start").Optional(),
		field.Time("updated").Optional(),
		field.Enum("lto").Values("enabled", "unknown", "disabled", "auto_disabled").Default("unknown").Optional(),
		// The version of the last build that published. A purge clears
		// repo_version and leaves this alone, making it the only record
		// seedBuildNo can recover a purged row from, so dropping it or ceasing
		// to write it reopens the filename reuse seeding exists to prevent.
		field.String("last_version_build").Optional(),
		// Highest version this row ever built, with the trailing pkgrel
		// component increasePkgRel owns stripped off, since upstream pkgrel 1
		// and 1.1 both publish into 1.N and share a filename namespace.
		field.String("max_version_base").Optional(),
		// Build number of the last build attempt. Only ever increments within
		// one max_version_base; together they keep published filenames unique,
		// see nextBuildNo.
		field.Int("build_no").Default(0).Optional(),
		field.Time("last_verified").Optional(),
		field.Enum("debug_symbols").Values("available", "unknown", "not_available").Default("unknown").Optional(),
		field.Int64("max_rss").Optional().Nillable(),
		field.Int64("u_time").Optional().Nillable(),
		field.Int64("s_time").Optional().Nillable(),
		field.Int64("io_in").Optional().Nillable(),
		field.Int64("io_out").Optional().Nillable(),
		field.String("tag_rev").Optional().Nillable(),
		field.Strings("sonames").Optional(),
	}
}

// Edges of the DBPackage.
func (DBPackage) Edges() []ent.Edge {
	return nil
}
