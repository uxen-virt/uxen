VBOX_VERSION_MAJOR=4
VBOX_VERSION_MINOR=2
VBOX_VERSION_BUILD=2

VBOX_SVN_REV=0

VBOX_VENDOR=uXenProject
VBOX_VENDOR_SHORT=uXenProject
VBOX_PRODUCT=uXen
VBOX_C_YEAR=2012

PATH_TMP=.

# Create auto-generated version file, needed by all modules
echo "#ifndef __version_generated_h__" > $PATH_TMP/version-generated.h
echo "#define __version_generated_h__" >> $PATH_TMP/version-generated.h
echo "" >> $PATH_TMP/version-generated.h
echo "#define VBOX_VERSION_MAJOR $VBOX_VERSION_MAJOR" >> $PATH_TMP/version-generated.h
echo "#define VBOX_VERSION_MINOR $VBOX_VERSION_MINOR" >> $PATH_TMP/version-generated.h
echo "#define VBOX_VERSION_BUILD $VBOX_VERSION_BUILD" >> $PATH_TMP/version-generated.h
echo "#define VBOX_VERSION_STRING \"$VBOX_VERSION_MAJOR.$VBOX_VERSION_MINOR.$VBOX_VERSION_BUILD\"" >> $PATH_TMP/version-generated.h
echo "" >> $PATH_TMP/version-generated.h
echo "#define VBOX_VERSION_MAJOR_NR $VBOX_VERSION_MAJOR" >> $PATH_TMP/version-generated.h
echo "#define VBOX_VERSION_MINOR_NR $VBOX_VERSION_MINOR" >> $PATH_TMP/version-generated.h
echo "#define VBOX_VERSION_BUILD_NR $VBOX_VERSION_BUILD" >> $PATH_TMP/version-generated.h
echo "" >> $PATH_TMP/version-generated.h
echo "#endif" >> $PATH_TMP/version-generated.h

# Create auto-generated revision file, needed by all modules
echo "#ifndef __revision_generated_h__" > $PATH_TMP/revision-generated.h
echo "#define __revision_generated_h__" >> $PATH_TMP/revision-generated.h
echo "" >> $PATH_TMP/revision-generated.h
echo "#define VBOX_SVN_REV $VBOX_SVN_REV" >> $PATH_TMP/revision-generated.h
echo "" >> $PATH_TMP/revision-generated.h
echo "#endif" >> $PATH_TMP/revision-generated.h

# Create auto-generated product file, needed by all modules
echo "#ifndef __product_generated_h__" > $PATH_TMP/product-generated.h
echo "#define __product_generated_h__" >> $PATH_TMP/product-generated.h
echo "" >> $PATH_TMP/product-generated.h
echo "#define VBOX_VENDOR \"$VBOX_VENDOR\"" >> $PATH_TMP/product-generated.h
echo "#define VBOX_VENDOR_SHORT \"$VBOX_VENDOR_SHORT\"" >> $PATH_TMP/product-generated.h
echo "" >> $PATH_TMP/product-generated.h
echo "#define VBOX_PRODUCT \"$VBOX_PRODUCT\"" >> $PATH_TMP/product-generated.h
echo "#define VBOX_C_YEAR \"$VBOX_C_YEAR\"" >> $PATH_TMP/product-generated.h
echo "" >> $PATH_TMP/product-generated.h
echo "#endif" >> $PATH_TMP/product-generated.h

