/** @file crule.h
 * @brief Interfaces and declarations for connection rule checking.
 * @version $Id: crule.h 1231 2004-10-05 04:21:37Z entrope $
 */
#ifndef INCLUDED_crule_h
#define INCLUDED_crule_h

/*
 * Proto types
 */

/*
 * opaque node pointer
 */
struct CRuleNode;

extern void crule_free(struct CRuleNode** elem);
extern int crule_eval(struct CRuleNode* rule);
extern struct CRuleNode* crule_parse(const char* rule);

#endif /* INCLUDED_crule_h */
