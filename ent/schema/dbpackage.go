package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// DbPackage holds the schema definition for the DbPackage entity.
type DbPackage struct {
	ent.Schema
}

// Fields of the DbPackage.
func (DbPackage) Fields() []ent.Field {
	return []ent.Field{
		field.String("pkgbase").NotEmpty().Immutable().Unique(),
		field.Strings("packages").Optional(),
		field.Enum("status").Values("skipped", "failed", "build", "queued", "building", "latest", "signing", "unknown").Default("unknown").Optional(),
		field.String("skip_reason").Optional(),
		field.Enum("repository").Values("extra", "core", "community"),
		field.String("march").NotEmpty(),
		field.String("version").Optional(),
		field.String("repo_version").Optional(),
		field.Time("build_time_start").Optional(),
		field.Time("build_time_end").Optional(),
		field.Time("updated").Optional(),
		field.String("hash").Optional(),
	}
}

// Edges of the DbPackage.
func (DbPackage) Edges() []ent.Edge {
	return nil
}
