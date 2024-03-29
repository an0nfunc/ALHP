// Code generated by ent, DO NOT EDIT.

package ent

import (
	"somegit.dev/ALHP/ALHP.GO/ent/dbpackage"
	"somegit.dev/ALHP/ALHP.GO/ent/schema"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	dbpackageFields := schema.DBPackage{}.Fields()
	_ = dbpackageFields
	// dbpackageDescPkgbase is the schema descriptor for pkgbase field.
	dbpackageDescPkgbase := dbpackageFields[0].Descriptor()
	// dbpackage.PkgbaseValidator is a validator for the "pkgbase" field. It is called by the builders before save.
	dbpackage.PkgbaseValidator = dbpackageDescPkgbase.Validators[0].(func(string) error)
	// dbpackageDescMarch is the schema descriptor for march field.
	dbpackageDescMarch := dbpackageFields[5].Descriptor()
	// dbpackage.MarchValidator is a validator for the "march" field. It is called by the builders before save.
	dbpackage.MarchValidator = dbpackageDescMarch.Validators[0].(func(string) error)
}
