/* 
 * This was derived from public domain works with updates to 
 * work with more modern SELinux libraries. 
 * 
 * It is released into the public domain.
 * 
 */

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/avrule_block.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/constraint.h>
#include <sepol/debug.h>

#ifdef WIN32
#define strtok_r strtok_s
#endif

int seinject_trace_level = 1;

void msg_write(sepol_handle_t *handle, int severity, char *label, char *func, char* format, ...)
{
	va_list ap;

	va_start(ap, format);

	if (seinject_trace_level < severity)
		return;

	fprintf(stderr, "%s (%s-%s): ",
		severity == SEPOL_MSG_ERR ? "error" :
		severity == SEPOL_MSG_WARN ? "warning" : "info",
		label, func);
	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

int seinject_msg(int severity, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	if (seinject_trace_level < severity)
		return severity;

	fprintf(stderr, "%s: ",
		severity == SEPOL_MSG_ERR ? "error" :
		severity == SEPOL_MSG_WARN ? "warning" : "info");
	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return severity;
}

void seinject_spec_to_string(uint16_t spec, char *buffer, size_t buflen)
{
	size_t			bufpos = 0;

	*buffer = 0;

	if (spec & AVTAB_ALLOWED)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " ALLOW");
	if (spec & AVTAB_AUDITALLOW)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " AUDITALLOW");
	if (spec & AVTAB_AUDITDENY)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " AUDITDENY");
	if (spec & AVTAB_NEVERALLOW)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " ANEVERALLOW");
	if (spec & AVTAB_TRANSITION)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " TRANSITION");
	if (spec & AVTAB_MEMBER)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " MEMBER");
	if (spec & AVTAB_CHANGE)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " CHANGE");
	if (spec & AVTAB_XPERMS_ALLOWED)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " XPERMS_ALLOWED");
	if (spec & AVTAB_XPERMS_AUDITALLOW)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " XPERMS_AUDITALLOW");
	if (spec & AVTAB_XPERMS_DONTAUDIT)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " XPERMS_DONTAUDIT");
	if (spec & AVTAB_XPERMS_NEVERALLOW)
		bufpos += snprintf(buffer + bufpos, buflen - bufpos, " XPERMS_NEVERALLOW");
}

size_t seinject_perm_to_string(char *buffer, size_t buflen, uint32_t value, class_datum_t *cls)
{
	size_t			bufpos = 0;
	hashtab_t		p;
	hashtab_ptr_t	*ptab, pcur;
	int				i, first = 1;

	*buffer = 0;

	for (i = 0; i < 2; i++) {
		p = i ? cls->permissions.table : (cls->comdatum ? cls->comdatum->permissions.table : 0);
		if (!p)
			continue;

		for (ptab = p->htable; ptab < p->htable + p->size; ptab++)
			for (pcur = *ptab; pcur; pcur = pcur->next)
				if (value & (1U << (((perm_datum_t*)(pcur->datum))->s.value - 1))) {
					bufpos += snprintf(buffer + bufpos, buflen - bufpos, first ? "%s" : ",%s", pcur->key);
					first = 0;
				}
	}

	return bufpos;
}

size_t seinject_dump_type_bm(char* buffer, size_t buflen, policydb_t *policy, ebitmap_t *bm)
{
	unsigned int	type_val;
	ebitmap_node_t	*node;
	int				first = 1;
	size_t			bufpos = 0;

	ebitmap_for_each_bit(bm, node, type_val) {
		if (ebitmap_node_get_bit(node, type_val)) {
			bufpos += snprintf(buffer + bufpos, buflen - bufpos, first ? "%s" : ",%s", policy->p_type_val_to_name[type_val]);
			first = 0;
		}
	}

	return bufpos;
}

size_t seinject_dump_expression(char* buffer, size_t buflen, policydb_t *policy, constraint_expr_t *exp)
{
	static const char *SE_CEXPR[] = { "", "==", "!=", "dom", "domby", "incomp" };
	uint32_t a = exp->attr;
	size_t	bufpos = 0;

	if (exp->expr_type >= CEXPR_NOT && exp->expr_type <= CEXPR_OR)
		return snprintf(buffer, buflen, " %s",
		exp->expr_type == CEXPR_NOT ? "!" :
		exp->expr_type == CEXPR_AND ? "&" : "|");


	if (exp->expr_type == CEXPR_ATTR) {
		if (a >= CEXPR_L1L2)
			return snprintf(buffer, buflen, " %s %s %s",
				a == CEXPR_L1L2 || a == CEXPR_L1H2 || a == CEXPR_L1H1 ? "l1" :
				a == CEXPR_H1L2 || a == CEXPR_H1H2 ? "h1" :
				a == CEXPR_L2H2 ? "l2" : "",
				SE_CEXPR[exp->op],
				a == CEXPR_L1L2 || a == CEXPR_H1L2 ? "l2" :
				a == CEXPR_L1H2 || a == CEXPR_H1H2 || a == CEXPR_L2H2 ? "h2" :
				a == CEXPR_L1H1 ? "h1" : "");
	}

	if (exp->expr_type == CEXPR_NAMES) {
		bufpos = snprintf(buffer, buflen, " %s%s %s ",
			(a & CEXPR_USER) ? "u" :
			(a & CEXPR_ROLE) ? "r" :
			(a & CEXPR_TYPE) ? "t" : "?",
			(a & CEXPR_TARGET) ? "2" : "1",
			SE_CEXPR[exp->op]);

		if (a & CEXPR_TYPE)
			bufpos += seinject_dump_type_bm(buffer + bufpos, buflen - bufpos, policy, &exp->type_names->types);
		else
			snprintf(buffer + bufpos, buflen - bufpos, "??");
	}

	return bufpos;
}

int seinject_dump_types(policydb_t *policy, char *filter)
{
	avtab_t			*t;
	avtab_ptr_t		*avtab;
	char			spec[1024];
	char			buffer[1024];
	int				bufpos;
	unsigned int	i;
	uint32_t		filter_type;

	if (filter) {
		type_datum_t *t = (type_datum_t*)hashtab_search(policy->p_types.table, filter);
		if (!t) {
			seinject_msg(SEPOL_MSG_ERR, "Filter type %s does not exist", filter);
			return 2;
		}
		filter_type = t->s.value;
	}

	for (i = 0; i < policy->p_types.nprim; i++) {
		type_datum_t	*td = policy->type_val_to_struct[i];

		unsigned int	type_val;
		ebitmap_node_t	*node;
		int				skip = filter ? 1 : 0, first = 1;

		if (filter && i + 1 == filter_type)
			skip = 0;

		bufpos = 0;
		bufpos += snprintf(buffer, sizeof(buffer), "[%s] %s (%s) {",
			td->flavor == 0 ? "TYPE" : td->flavor == 1 ? "ATTRIB" : "ALIAS",
			policy->p_type_val_to_name[i],
			(td->flags & 0x01) == 0 ? "ENFORCING" : "PERMISSIVE");

		ebitmap_for_each_bit(policy->type_attr_map + i, node, type_val) {
			if (ebitmap_node_get_bit(node, type_val)) {
				if (filter && type_val + 1 == filter_type)
					skip = 0;

				bufpos += snprintf(buffer + bufpos, sizeof(buffer) - bufpos, first ? "%s" : ",%s", policy->p_type_val_to_name[type_val]);
				first = 0;
			}
		}

		if (!skip)
			printf("%s}\n", buffer);
	}

	t = &policy->te_avtab;
	for (avtab = t->htable; avtab < t->htable + t->nslot; avtab++) {
		avtab_ptr_t	cur;

		for (cur = *avtab; cur; cur = cur->next) {
			avtab_key_t		*key = &cur->key;

			if (filter && key->source_type != filter_type && key->target_type != filter_type &&
				(0 == (AVTAB_TRANSITION & key->specified) || cur->datum.data != filter_type))
				continue;

			seinject_spec_to_string(key->specified, spec, sizeof(spec));

			bufpos = snprintf(buffer, sizeof(buffer), "[AV] %s %s -> %s (%s) {", spec + 1,
				policy->p_type_val_to_name[key->source_type - 1],
				policy->p_type_val_to_name[key->target_type - 1],
				policy->p_class_val_to_name[key->target_class - 1]);

			if (0 == (AVTAB_TRANSITION & key->specified))
				bufpos += seinject_perm_to_string(buffer + bufpos, sizeof(buffer) - bufpos, cur->datum.data, policy->class_val_to_struct[key->target_class - 1]);
			else
				bufpos += snprintf(buffer + bufpos, sizeof(buffer) - bufpos, "%s", policy->p_type_val_to_name[cur->datum.data - 1]);

			bufpos += snprintf(buffer + bufpos, sizeof(buffer) - bufpos, "}\n");
			printf(buffer);
		}
	}

	return 0;
}


int seinject_dump_classes(policydb_t *policy, char *filter)
{
	char			buffer[1024];
	int				cat_min, cat_max;

	unsigned int	i;

	uint32_t		filter_class;
	int				bufpos;

	if (filter) {
		class_datum_t *t = (class_datum_t*)hashtab_search(policy->p_classes.table, filter);
		if (!t)
			return seinject_msg(SEPOL_MSG_ERR, "Filter class %s does not exist", filter);
		filter_class = t->s.value;
	}

	for (i = 0; i < policy->p_levels.nprim; i++)
		printf("[LEVEL] %s\n", policy->p_sens_val_to_name[i]);

	
	for (cat_min = 65535, cat_max = 0, i = 0; i < policy->p_cats.nprim; i++) {
		char	*name = policy->p_cat_val_to_name[i];
		int		cat;

		if ((name)[0] != 'c') {
			printf("[CAT] %s\n", name);
			continue;
		}
		cat = atoi((name) + 1);
		if (cat_min > cat)
			cat_min = cat;
		if (cat_max < cat)
			cat_max = cat;
	}
	printf("[CATS] c%d.c%d\n", cat_min, cat_max);

	for (i = (filter ? filter_class : 0); i < (filter ? filter_class + 1 : policy->p_classes.nprim); i++)
		printf("[CLASS] %s\n", policy->p_class_val_to_name[i]);


	for (i = (filter ? filter_class : 0); i < (filter ? filter_class + 1 : policy->p_classes.nprim); i++) {
		constraint_node_t	*ccur;
		constraint_expr_t	*ecur;
		class_datum_t		*cd = policy->class_val_to_struct[i];

		for (ccur = cd->constraints; ccur; ccur = ccur->next) {
			bufpos = 0;
			bufpos = snprintf(buffer, sizeof(buffer), "[CONSTRAINT] %s {", policy->p_class_val_to_name[i]);
			bufpos += seinject_perm_to_string(buffer + bufpos, sizeof(buffer) - bufpos, ccur->permissions, cd);
			bufpos += snprintf(buffer + bufpos, sizeof(buffer) - bufpos, "} ");

			for (ecur = ccur->expr; ecur; ecur = ecur->next) {
				if (ecur->next && ecur->next->expr_type >= CEXPR_NOT && ecur->next->expr_type <= CEXPR_OR) {
					bufpos += seinject_dump_expression(buffer + bufpos, sizeof(buffer) - bufpos, policy, ecur->next);
					bufpos += seinject_dump_expression(buffer + bufpos, sizeof(buffer) - bufpos, policy, ecur);
					ecur = ecur->next;
					continue;
				}

				bufpos += seinject_dump_expression(buffer + bufpos, sizeof(buffer) - bufpos, policy, ecur);
			}
			printf("%s\n", buffer);
		}
	}

	return 0;
}

int seinject_dump_genfs(policydb_t *policy, char *filter)
{
	uint32_t		filter_type;
	genfs_t			*cur;

	if (filter) {
		type_datum_t *t = (type_datum_t*)hashtab_search(policy->p_types.table, filter);
		if (!t) {
			seinject_msg(SEPOL_MSG_ERR, "Filter type %s does not exist", filter);
			return 2;
		}
		filter_type = t->s.value;
	}

	for (cur = policy->genfs; cur; cur = cur->next) {
		ocontext_t		*octx;

		for (octx = cur->head; octx; octx = octx->next) {
			uint32_t	t = octx->context[0].type;

			if (filter && filter_type != !t)
				continue;

			printf("[GENFS] %s %s {%s}\n", cur->fstype, octx->u.name,
				policy->p_type_val_to_name[t - 1]);
		}
	}
	return 0;
}


void *cmalloc(size_t s)
{
	void *t = malloc(s);
	if (t == NULL) {
		seinject_msg(SEPOL_MSG_ERR, "Out of memory");
		exit(1);
	}
	return t;
}

int policydb_index_decls(sepol_handle_t * handle, policydb_t * p);

int add_type(policydb_t *policy, char *type, type_datum_t** td_ret)
{
	type_datum_t	*td;
	uint32_t		value = 0;
	char*			name;
	unsigned int	i;

	td = (type_datum_t *)cmalloc(sizeof(type_datum_t));
	type_datum_init(td);
	td->primary = 1;
	td->flavor = TYPE_TYPE;

	name = strdup(type);
	if (!name)
		return seinject_msg(SEPOL_MSG_ERR, "Could allocate memor for new type", type);

	if (SEPOL_OK != symtab_insert(policy, SYM_TYPES, name, td, SCOPE_DECL, 1, &value))
		return seinject_msg(SEPOL_MSG_ERR, "Failed to insert type into symtab\n");

	td->s.value = value;

	if (ebitmap_set_bit(&policy->global->branch_list->declared.scope[SYM_TYPES], value - 1, 1)) {
		exit(1);
	}

	policy->type_attr_map = realloc(policy->type_attr_map, sizeof(ebitmap_t)*policy->p_types.nprim);
	policy->attr_type_map = realloc(policy->attr_type_map, sizeof(ebitmap_t)*policy->p_types.nprim);
	ebitmap_init(&policy->type_attr_map[value - 1]);
	ebitmap_init(&policy->attr_type_map[value - 1]);
	ebitmap_set_bit(&policy->type_attr_map[value - 1], value - 1, 1);


	for (i = 0; i<policy->p_roles.nprim; ++i) {
		//Not sure all those three calls are needed
		ebitmap_set_bit(&policy->role_val_to_struct[i]->types.negset, value - 1, 0);
		ebitmap_set_bit(&policy->role_val_to_struct[i]->types.types, value - 1, 1);
		type_set_expand(&policy->role_val_to_struct[i]->types, &policy->role_val_to_struct[i]->cache, policy, 0);
	}

	if (policydb_index_decls(0, policy))
		return seinject_msg(SEPOL_MSG_ERR, "Failed to index decls\n");

	if (policydb_index_classes(policy))
		return seinject_msg(SEPOL_MSG_ERR, "Failed to index classes\n");
	
	if (policydb_index_others(NULL, policy, 1))
		return seinject_msg(SEPOL_MSG_ERR, "Failed to index others\n");

	*td_ret = td;
	return 0;
}

int madd_rule(policydb_t *policy, char *s, char *t, char *c, char *p)
{
	type_datum_t *src, *tgt;
	class_datum_t *cls;
	perm_datum_t *perm;
	avtab_datum_t *av;
	avtab_key_t key;
	unsigned int	src_type, tgt_type;
	ebitmap_node_t	*src_node, *tgt_node;

	src = (type_datum_t*)hashtab_search(policy->p_types.table, s);
	if (src == NULL)
		return seinject_msg(SEPOL_MSG_WARN, "source type %s does not exist", s);

	tgt = (type_datum_t*)hashtab_search(policy->p_types.table, t);
	if (tgt == NULL)
		return seinject_msg(SEPOL_MSG_WARN, "target type %s does not exist", t);

	cls = (class_datum_t*)hashtab_search(policy->p_classes.table, c);
	if (cls == NULL)
		return seinject_msg(SEPOL_MSG_WARN, "class %s does not exist", c);

	perm = (perm_datum_t*)hashtab_search(cls->permissions.table, p);
	if (perm == NULL) {
		if (cls->comdatum == NULL)
			return seinject_msg(SEPOL_MSG_WARN, "perm %s does not exist in class %s", p, c);

		perm = (perm_datum_t*)hashtab_search(cls->comdatum->permissions.table, p);
		if (perm == NULL)
			return seinject_msg(SEPOL_MSG_WARN, "perm %s does not exist in class %s", p, c);
	}

	key.target_class = cls->s.value;
	key.specified = AVTAB_ALLOWED;

	/* Check if this permission exist already */
	ebitmap_for_each_bit(policy->type_attr_map + src->s.value - 1, src_node, src_type) {
		if (!ebitmap_node_get_bit(src_node, src_type))
			continue;

		ebitmap_for_each_bit(policy->type_attr_map + tgt->s.value - 1, tgt_node, tgt_type) {
			if (!ebitmap_node_get_bit(tgt_node, tgt_type))
				continue;

			key.source_type = src_type + 1;
			key.target_type = tgt_type + 1;
			av = avtab_search(&policy->te_avtab, &key);
			if (!av)
				continue;

			if (!(av->data & (1U << (perm->s.value - 1))))
				continue;

			return seinject_msg(SEPOL_MSG_WARN, "Permission {%s} %s (%s) -> %s (%s) %s already exists",
				p, s, policy->p_type_val_to_name[src_type],
				t, policy->p_type_val_to_name[tgt_type], c);
		}
	}

	// See if there is already a rule
	key.source_type = src->s.value;
	key.target_type = tgt->s.value;
	av = avtab_search(&policy->te_avtab, &key);

	if (av == NULL) {
		int ret;

		av = (avtab_datum_t*)cmalloc(sizeof av);
		av->data |= 1U << (perm->s.value - 1);
		ret = avtab_insert(&policy->te_avtab, &key, av);
		if (ret)
			return seinject_msg(SEPOL_MSG_ERR, "Error inserting into avtab");
	}

	av->data |= 1U << (perm->s.value - 1);

	return 0;
}

int add_genfs(policydb_t *policy, char *fs, char *p, char *c)
{
	type_datum_t		*tgt;
	genfs_t				*genfs;
	ocontext_t			*octx;
	context_struct_t	*ctx;
	char				*path;

	path = p ? p : "/";

	tgt = (type_datum_t*)hashtab_search(policy->p_types.table, c);
	if (tgt == NULL)
		return seinject_msg(SEPOL_MSG_WARN, "target type %s does not exist", c);

	for (genfs = policy->genfs; genfs; genfs = genfs->next) {
		if (strcmp(genfs->fstype, fs))
			continue;

		for (octx = genfs->head; octx; octx = octx->next) {
			if (0 == strcmp(octx->u.name, path)) {
				octx->context[0].type = tgt->s.value;
				return 0;
			}
		}

		octx = (ocontext_t*)malloc(sizeof(ocontext_t));
		memset(octx, 0, sizeof(ocontext_t));
		octx->next = genfs->head;
		genfs->head = octx;
		break;
	}

	if (!genfs) {
		genfs = (genfs_t*)malloc(sizeof(genfs_t));
		genfs->fstype = strdup(fs);
		octx = (ocontext_t*)malloc(sizeof(ocontext_t));
		memset(octx, 0, sizeof(ocontext_t));
		genfs->head = octx;
		genfs->next = policy->genfs;
		policy->genfs = genfs;
	}

	octx->u.name = strdup(path);

	ctx = octx->context;
	ctx->user = 1;
	ctx->role = 1;
	ctx->type = tgt->s.value;
	ctx->range.level[0].sens = 1;
	ctx->range.level[1].sens = 1;
	return 0;
}

int madd_transition(policydb_t *policy, char *srcS, char *origS, char *tgtS, char *c)
{
	type_datum_t *src, *tgt, *orig;
	class_datum_t *cls;

	avtab_datum_t *av;
	avtab_key_t key;

	src = hashtab_search(policy->p_types.table, srcS);
	if (src == NULL)
		return seinject_msg(SEPOL_MSG_WARN, "source type %s does not exist\n", srcS);

	tgt = hashtab_search(policy->p_types.table, tgtS);
	if (tgt == NULL)
		return seinject_msg(SEPOL_MSG_WARN, "target type %s does not exist\n", tgtS);

	cls = hashtab_search(policy->p_classes.table, c);
	if (cls == NULL)
		return seinject_msg(SEPOL_MSG_WARN, "class %s does not exist\n", c);

	orig = hashtab_search(policy->p_types.table, origS);
	if (cls == NULL)
		return seinject_msg(SEPOL_MSG_WARN, "class %s does not exist\n", origS);

	key.source_type = src->s.value;
	key.target_type = orig->s.value;
	key.target_class = cls->s.value;
	key.specified = AVTAB_TRANSITION;
	av = avtab_search(&policy->te_avtab, &key);

	if (av)
		return seinject_msg(SEPOL_MSG_WARN, "Warning, rule already defined! Won't override.\n"
			"Previous value = %d, wanted value = %d\n", av->data, tgt->s.value);

	av = cmalloc(sizeof(*av));
	av->data = tgt->s.value;
	int ret = avtab_insert(&policy->te_avtab, &key, av);
	if (ret)
		return seinject_msg(SEPOL_MSG_ERR, "Error inserting into avtab\n");

	return 0;
}

int add_attr(policydb_t *policy, char *type, char *attr)
{
	type_datum_t		*td, *ad;
	unsigned int		i;

	td = hashtab_search(policy->p_types.table, type);
	if (!td)
		return seinject_msg(SEPOL_MSG_WARN, "type %s does not exist\n", type);

	ad = hashtab_search(policy->p_types.table, attr);
	if (!ad)
		return seinject_msg(SEPOL_MSG_WARN, "attribute %s does not exist\n", attr);

	if (ad->flavor != TYPE_ATTRIB)
		return seinject_msg(SEPOL_MSG_ERR, "%s is not an attribute", type);

	if (ebitmap_set_bit(policy->type_attr_map + td->s.value - 1, ad->s.value - 1, 1))
		return seinject_msg(SEPOL_MSG_ERR, "error setting attibute %s for type: %s", attr, type);

	if (ebitmap_set_bit(policy->attr_type_map + ad->s.value - 1, td->s.value - 1, 1))
		return seinject_msg(SEPOL_MSG_ERR, "error setting attibute %s for type: %s", attr, type);

	/* Update constraints */
	for (i = 0; i < policy->p_classes.nprim; i++) {
		constraint_node_t	*n;
		constraint_expr_t	*e;
		class_datum_t		*cl = policy->class_val_to_struct[i];

		for (n = cl->constraints; n; n = n->next)
			for (e = n->expr; e; e = e->next)
				if (e->expr_type == CEXPR_NAMES)
					if (ebitmap_get_bit(&e->type_names->types, ad->s.value - 1))
						ebitmap_set_bit(&e->names, td->s.value - 1, 1);
	}

	return 0;
}

int remove_mls_contraints(policydb_t *policy, char *clazz) {
	class_datum_t	*cd;

	cd = hashtab_search(policy->p_classes.table, clazz);
	if (!cd)
		return seinject_msg(SEPOL_MSG_WARN, "class %s does not exist\n");

	cd->constraints = 0;
	return 0;
}

int load_policy(char *filename, policydb_t *policydb, struct policy_file *pf)
{
	FILE*	f;
	size_t	size;
	void *data;
	int ret;

	f = fopen(filename, "rb");
	if (f == NULL) {
		seinject_msg(SEPOL_MSG_ERR, "Can't open '%s':  %s", filename, strerror(errno));
		exit(1);
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);

	data = malloc(size);
	if (data == NULL) {
		fclose(f);
		seinject_msg(SEPOL_MSG_ERR, "Can't allocate memory");
		exit(1);
	}

	if (fread(data, 1, size, f) != size) {
		free(data);
		fclose(f);
		seinject_msg(SEPOL_MSG_ERR, "Can't read policy file '%s':  %s", filename, strerror(errno));
		exit(1);
	}

	policy_file_init(pf);
	pf->type = PF_USE_MEMORY;
	pf->data = (char*)data;
	pf->len = size;
	if (policydb_init(policydb)) {
		free(data);
		fclose(f);
		seinject_msg(SEPOL_MSG_ERR, "policydb_init: Out of memory!");
		exit(1);
	}

	ret = policydb_read(policydb, pf, 1);
	if (ret) {
		free(data);
		fclose(f);
		seinject_msg(SEPOL_MSG_ERR, "error(s) encountered while parsing configuration");
		exit(1);
	}

	free(data);
	fclose(f);
	return 0;
}

int load_policy_into_kernel(policydb_t *policydb)
{
	FILE	*f;
	char *filename = "/sys/fs/selinux/load";
	int ret;
	void *data = NULL;
	size_t len;

	policydb_to_image(NULL, policydb, &data, &len);

	// based on libselinux security_load_policy()
	f = fopen(filename, "wb");
	if (f == NULL) {
		seinject_msg(SEPOL_MSG_ERR, "Can't open '%s':  %s", filename, strerror(errno));
		exit(1);
	}

	ret = fwrite(data, 1, len, f);
	fclose(f);

	if (ret < 0) {
		seinject_msg(SEPOL_MSG_ERR, "Could not write policy to %s", filename);
		exit(1);
	}

	return 0;
}

int main_seinject(int argc, char **argv)
{
	char				*policy = NULL, *source = NULL, *target = NULL, *clazz = NULL, *perm = NULL, *fcon = 0;
	char				*mls = 0, *perm_token = NULL, *perm_saveptr = NULL, *outfile = NULL;
	char				*type = 0, *genfs = 0, *attr = 0;
	policydb_t			policydb;
	struct policy_file	pf, outpf;
	sidtab_t			sidtab;
	int					load = 0, dump_types = 0, dump_classes = 0, dump_genfs = 0;
	FILE				*fp;
	int					rc, i, permissive_value = 0;

	for (i=1; i<argc; i++) {
		if (argv[i][0] == '-') {

			if (argv[i][1] == 'a') {
				i++;
				attr = argv[i];
				continue;
			}
			if (argv[i][1] == 'c') {
				i++;
				clazz = argv[i];
				continue;
			}
			if (argv[i][1] == 'd') {
				if (argv[i][2] == 't') {
					dump_types = 1;
					continue;
				}
				else if (argv[i][2] == 'c') {
					dump_classes = 1;
					continue;
				}
				else if (argv[i][2] == 'g') {
					dump_genfs = 1;
					continue;
				}
			}
			if (argv[i][1] == 'f') {
				i++;
				fcon = argv[i];
				continue;
			}
			if (argv[i][1] == 'g') {
				i++;
				genfs = argv[i];
				continue;
			}
			if (argv[i][1] == 'l') {
				load = 1;
				continue;
			}
			if (argv[i][1] == 'M') {
				i++;
				mls = argv[i];
				continue;
			}
			if (argv[i][1] == 'o') {
				i++;
				outfile = argv[i];
				continue;
			}
			if (argv[i][1] == 'p') {
				i++;
				perm = argv[i];
				continue;
			}
			if (argv[i][1] == 'P') {
				i++;
				policy = argv[i];
				continue;
			}
			if (argv[i][1] == 's') {
				i++;
				source = argv[i];
				continue;
			}
			if (argv[i][1] == 't') {
				i++;
				target = argv[i];
				continue;
			}
			if (argv[i][1] == 'w') {
				i++;
				seinject_trace_level = atoi(argv[i]);
				continue;
			}
			if (argv[i][1] == 'Z') {
				i++;
				type = argv[i];
				permissive_value = 1;
				continue;
			}
			if (argv[i][1] == 'z') {
				i++;
				type = argv[i];
				permissive_value = 0;
				continue;
			}
			break;
		}
	}

	if (i < argc || argc == 1 || ((!source || !target || !clazz || !perm) && !attr && !fcon && !type && !mls && !dump_types && !dump_classes && !dump_genfs &&(!genfs || !target))) {
		fprintf(stderr, "   -l\n");
		fprintf(stderr, "    Set trace level 0-3 (default 1)\n\n");
		fprintf(stderr, "%s -s <source type> -t <target type> -c <class> -p <perm>[,<perm2>,<perm3>,...] [-P <policy file>] [-o <output file>] [-l|--load]\n", argv[0]);
		fprintf(stderr, "    Add AV rule\n\n");
		fprintf(stderr, "%s -Z permissive_type [-P <policy file>] [-o <output file>] [-l|--load]\n", argv[0]);
		fprintf(stderr, "    Add permissive type\n\n");
		fprintf(stderr, "%s -z <source type> -P <policy file> [-o <output file>]\n", argv[0]);
		fprintf(stderr, "    Add enforcing type\n\n");
		fprintf(stderr, "%s -s <source type> -a <type_attribute> -P <policy file> [-o <output file>]\n", argv[0]);
		fprintf(stderr, "    Add attribute to type\n\n");
		fprintf(stderr, "%s -g file system -t <target type> [-p path ] [-P <policy file>] [-o <output file>] [-l|--load]\n", argv[0]);
		fprintf(stderr, "    Add genfs entry\n\n");
		fprintf(stderr, "%s -M class [-p path ] [-P <policy file>] [-o <output file>] [-l|--load]\n", argv[0]);
		fprintf(stderr, "    Remove contraints from class\n\n");
		fprintf(stderr, "%s -dt [-t type] [-p path ] [-P <policy file>]\n", argv[0]);
		fprintf(stderr, "    Dump types and AV rules, filtered by optional type\n\n");
		fprintf(stderr, "%s -dc [-p path ] [-P <policy file>]\n", argv[0]);
		fprintf(stderr, "    Dump classes and constraints\n\n");
		exit(1);
	}

	if (!policy)
		policy = "/sys/fs/selinux/policy";

	sepol_set_policydb(&policydb);
	sepol_set_sidtab(&sidtab);

	if (load_policy(policy, &policydb, &pf)) {
		seinject_msg(SEPOL_MSG_ERR, "Could not load policy");
		exit(1);
	}

	if (policydb_load_isids(&policydb, &sidtab))
		return 1;

	if (dump_types || dump_classes || dump_genfs) {
		if (dump_classes)
			seinject_dump_classes(&policydb, clazz);

		if (dump_types)
			seinject_dump_types(&policydb, target);

		if (dump_genfs)
			seinject_dump_genfs(&policydb, target);

		return 0;
	}

	if (type) {
		/* Set domain permissive / non-permissive */
		type_datum_t *td = hashtab_search(policydb.p_types.table, type);

		if (!td) {
			rc = add_type(&policydb, type, &td);
			if (SEPOL_OK != rc) {
				seinject_msg(rc, "Could not create type %s", type);
				exit(rc);
			}
		}

		if (ebitmap_set_bit(&policydb.permissive_map, td->s.value, permissive_value)) {
			seinject_msg(SEPOL_MSG_ERR, "Could not set bit in permissive map");
			exit(2);
		}
	} else if (genfs) {
		/* Add genfs entry */
		rc = add_genfs(&policydb, genfs, perm, target);
		if (SEPOL_OK != rc) {
			seinject_msg(rc, "Could not add genfs rule");
			exit(rc);
		}

	} else if (mls) {
		remove_mls_contraints(&policydb, mls);

	} else if (fcon) {
		rc = madd_transition(&policydb, source, fcon, target, clazz);
		if (SEPOL_OK != rc) {
			seinject_msg(rc, "Could not add file transition rule");
			exit(rc);
		}

	} else if (attr) {
		rc = add_attr(&policydb, source, attr);
		if (SEPOL_OK != rc) {
			seinject_msg(rc, "Could not add attr to type");
			exit(rc);
		}

	} else {
		int	rc_total = SEPOL_OK;

		perm_token = strtok_r(perm, ",", &perm_saveptr);
		while (perm_token) {
			rc = madd_rule(&policydb, source, target, clazz, perm_token);
			if (rc > rc_total)
				rc_total = rc;
			perm_token = strtok_r(NULL, ",", &perm_saveptr);
		}

		if (SEPOL_OK != rc_total)
			exit(rc);
	}

	if (outfile) {
		fp = fopen(outfile, "wb");
		if (!fp) {
			seinject_msg(SEPOL_MSG_ERR, "Could not open outfile");
			exit(1);
		}

		policy_file_init(&outpf);
		outpf.type = PF_USE_STDIO;
		outpf.fp = fp;

		if (policydb_write(&policydb, &outpf)) {
			seinject_msg(SEPOL_MSG_ERR, "Could not write policy");
			exit(1);
		}

		fclose(fp);
	}

	if (load) {
		if (load_policy_into_kernel(&policydb)) {
			seinject_msg(SEPOL_MSG_ERR, "Could not load new policy into kernel");
			exit(1);
		}
	}

	policydb_destroy(&policydb);
	return 0;
}
