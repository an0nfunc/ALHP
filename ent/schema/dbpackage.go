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
		field.Int("status").Optional().Min(0),
		field.String("skip_reason").Optional(),
		field.String("repository").NotEmpty(),
		field.String("march").NotEmpty(),
		field.String("version").Optional(),
		field.String("repo_version").Optional(),
		field.Time("build_time").Optional(),
		field.Uint64("build_duration").Positive().Optional(),
		field.Time("updated").Optional(),
	}
}

// Edges of the DbPackage.
func (DbPackage) Edges() []ent.Edge {
	return nil
}
