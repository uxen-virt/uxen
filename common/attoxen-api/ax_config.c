/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "ax_config.h"

static char *indent (unsigned i)
{
  static char space[] = "                                              ";

  if (i >= sizeof (space)) i = sizeof (space) - 1;

  return space + ((sizeof (space) - 1) - i);
}


static int ax_config_bounds_check_node (unsigned num)
{
  num *= sizeof (ax_config_node_t);

  if (num >= ax_config_len) return 1;

  num += sizeof (ax_config_node_t);

  if (num > ax_config_len) return 1;

  return 0;
}

static int ax_config_bounds_check_string (unsigned offset)
{
  const char *ptr = (const char *) ax_config_tree;

  if (offset >= ax_config_len) return 1;

  ptr += offset;

  while (offset < ax_config_len) {

    if (!*ptr)  return 0;

    ptr++;
    offset++;

    if (!offset) return 1;
  }

  return 1;
}



ax_config_type_t   ax_config_node_type (unsigned num)
{
  const ax_config_node_t *n;

  if (!num  || !ax_config_tree) return AX_CONFIG_TYPE_RESERVED;

  if (ax_config_bounds_check_node (num)) return AX_CONFIG_TYPE_RESERVED;

  n = &ax_config_tree[num];

  return n->type;
}

unsigned ax_config_node_next (unsigned num)
{
  const ax_config_node_t *n;

  if (!ax_config_tree || !num) return 0;

  if (ax_config_bounds_check_node (num)) return 0;

  n = &ax_config_tree[num];

  if (n->next <= num) return 0;

  return n->next;
}


unsigned ax_config_node_value (unsigned num)
{
  const ax_config_node_t *n;

  if (!ax_config_tree || !num) return 0;

  if (ax_config_bounds_check_node (num)) return 0;

  n = &ax_config_tree[num];


  return n->value;
}


const char *ax_config_node_type_str (unsigned num)
{
  const ax_config_node_t *n;

  if (!ax_config_tree || !num) return "Null";

  n = &ax_config_tree[num];

  switch (n->type) {
  case AX_CONFIG_TYPE_RESERVED :
    return "AX_CONFIG_TYPE_RESERVED ";

  case AX_CONFIG_TYPE_KEY :
    return "AX_CONFIG_TYPE_KEY ";

  case AX_CONFIG_TYPE_NULL :
    return "AX_CONFIG_TYPE_NULL ";

  case AX_CONFIG_TYPE_BOOLEAN :
    return "AX_CONFIG_TYPE_BOOLEAN ";

  case AX_CONFIG_TYPE_INTEGER :
    return "AX_CONFIG_TYPE_INTEGER ";

  case AX_CONFIG_TYPE_STRING :
    return "AX_CONFIG_TYPE_STRING ";

  case AX_CONFIG_TYPE_MAP :
    return "AX_CONFIG_TYPE_MAP ";

  default:
    return "Unknown";
  }

}

int ax_config_node_integer (unsigned num)
{
  const ax_config_node_t *n;

  if (!ax_config_tree || !num) return 0;

  if (ax_config_bounds_check_node (num)) return 0;

  n = &ax_config_tree[num];
  return n->integer;
}


const char *ax_config_node_string (unsigned num)
{
  const ax_config_node_t *n;
  const char *ret = (const char *) ax_config_tree;

  if (!ax_config_tree || !num) return NULL;

  if (ax_config_bounds_check_node (num)) return NULL;

  n  = &ax_config_tree[num];

  if ((n->type != AX_CONFIG_TYPE_STRING) && (n->type != AX_CONFIG_TYPE_KEY))
    return NULL;

  if (ax_config_bounds_check_string (n->string_offset))
    return NULL;


  ret += n->string_offset;

  return ret;
}


static void dump_node (unsigned num, int i);

static void dump_values (unsigned num, int i)
{
  const ax_config_node_t *n;

  if (!ax_config_tree) return;

  while (num) {

    n = &ax_config_tree[num];

    switch (n->type) {

    case AX_CONFIG_TYPE_MAP:
      if (i < CONFIG_TREE_MAX_DEPTH)
        dump_node (num, i);
      else
        ax_config_print ("%s-value: ERROR TREE TOO DEEP\n", indent (i));

      break;

    case AX_CONFIG_TYPE_NULL:
      ax_config_print ("%s-value: null\n", indent (i));
      break;

    case AX_CONFIG_TYPE_BOOLEAN:
      ax_config_print ("%-svalue: boolean %d\n", indent (i), n->integer);
      break;

    case AX_CONFIG_TYPE_INTEGER:
      ax_config_print ("%s-value: integer %d\n", indent (i), n->integer);
      break;

    case AX_CONFIG_TYPE_STRING:
      ax_config_print ("%s-value: sting %s\n", indent (i), ax_config_node_string (num));
      break;


    default:
      ax_config_print ("%s-Unexpected type!\n", indent (i));
    }


    num = ax_config_node_value (num);
  }

}

static  void dump_node (unsigned num, int i)
{
  const ax_config_node_t *n;

  if (!ax_config_tree) return;

  while (num) {

    n = &ax_config_tree[num];

    switch (n->type) {
    case AX_CONFIG_TYPE_MAP:
      ax_config_print ("%s-map\n", indent (i));
      i++;
      break;

    case AX_CONFIG_TYPE_KEY:
      ax_config_print ("%s-key %s\n", indent (i), ax_config_node_string (num));
      dump_values (n->value, i + 1);
      break;

    default:
      ax_config_print ("%s-Unexpected type!\n", indent (i));
    }

    num = ax_config_node_next (num);
  }

}




void ax_config_dump()
{
  dump_node (CONFIG_TREE_START, 0);
}

static int ax_config_strcmp (const char *s1, const char *s2)
{
  for (;; s1++, s2++) {
    if (*s1 > *s2)
      return 1;

    if (*s1 < *s2)
      return -1;

    if (!*s1)
      return 0;
  }

  return 0;
}

unsigned ax_config_get_value (unsigned n, const char *key)
{
  const char *n_key;

  if (!ax_config_tree) return 0;

  while (n) {

    switch (ax_config_node_type (n)) {
    case AX_CONFIG_TYPE_KEY:
      n_key = ax_config_node_string (n);

      if (!n_key) break;

      if (!ax_config_strcmp (key, n_key))
        return ax_config_node_value (n);

    default:
      break;
    }

    n = ax_config_node_next (n);
  }


  return 0;
}

unsigned ax_config_get_value2 (unsigned n, const char *key1, const char *key2)
{
  n = ax_config_get_value (n, key1);
  n = ax_config_get_value (n, key2);
  return n;
}

unsigned ax_config_get_value3 (unsigned n, const char *key1, const char *key2, const char *key3)
{
  n = ax_config_get_value (n, key1);
  n = ax_config_get_value (n, key2);
  n = ax_config_get_value (n, key3);
  return n;
}



int ax_config_get_boolean (unsigned n, const char *key, int *v)
{
  n = ax_config_get_value (n, key);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_BOOLEAN) return -1;

  *v = ax_config_node_integer (n);

  return 0;
}



int ax_config_get_integer (unsigned n, const char *key, int *v)
{
  n = ax_config_get_value (n, key);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_INTEGER) return -1;

  *v = ax_config_node_integer (n);

  return 0;
}


const char *ax_config_get_string (unsigned n, const char *key, const char **str)
{
  const char *ret;
  n = ax_config_get_value (n, key);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_STRING) return NULL;

  ret = ax_config_node_string (n);

  if (*str) *str = ret;

  return ret;
}



int ax_config_get_boolean2 (unsigned n, const char *key1, const char *key2, int *v)
{
  n = ax_config_get_value (n, key1);
  n = ax_config_get_value (n, key2);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_BOOLEAN) return -1;

  *v = ax_config_node_integer (n);

  return 0;
}



int ax_config_get_integer2 (unsigned n, const char *key1, const char *key2, int *v)
{
  n = ax_config_get_value (n, key1);
  n = ax_config_get_value (n, key2);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_INTEGER) return -1;

  *v = ax_config_node_integer (n);

  return 0;
}


const char *ax_config_get_string2 (unsigned n, const char *key1, const char *key2, const char **str)
{
  const char *ret;

  n = ax_config_get_value (n, key1);
  n = ax_config_get_value (n, key2);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_STRING) return NULL;

  ret = ax_config_node_string (n);

  if (*str) *str = ret;

  return ret;
}



int ax_config_get_boolean3 (unsigned n, const char *key1, const char *key2, const char *key3, int *v)
{
  n = ax_config_get_value (n, key1);
  n = ax_config_get_value (n, key2);
  n = ax_config_get_value (n, key3);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_BOOLEAN) return -1;

  *v = ax_config_node_integer (n);

  return 0;
}



int ax_config_get_integer3 (unsigned n, const char *key1, const char *key2, const char *key3, int *v)
{
  n = ax_config_get_value (n, key1);
  n = ax_config_get_value (n, key2);
  n = ax_config_get_value (n, key3);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_INTEGER) return -1;

  *v = ax_config_node_integer (n);

  return 0;
}


const char *ax_config_get_string3 (unsigned n, const char *key1, const char *key2, const char *key3, const char **str)
{
  const char *ret;

  n = ax_config_get_value (n, key1);
  n = ax_config_get_value (n, key2);
  n = ax_config_get_value (n, key3);

  if (ax_config_node_type (n) != AX_CONFIG_TYPE_STRING) return NULL;

  ret = ax_config_node_string (n);

  if (*str) *str = ret;

  return ret;

}
