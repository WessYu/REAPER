# Implemented rules

All findings in 0.1.0 are static/catalog observations. None use CONFIRMED confidence.

| Rule              | Evidence                                                                                    | Severity / confidence | Important boundary                                                            |
| ----------------- | ------------------------------------------------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------- |
| REAPER-SQL-001    | HTTP input flows into a supported SQL text argument                                         | HIGH / HIGH           | Bound value arrays and Prisma tagged templates are not SQL text interpolation |
| REAPER-SQL-002    | Parsed constant UPDATE/DELETE has no WHERE                                                  | MEDIUM / HIGH         | Whole-table maintenance can be intentional                                    |
| REAPER-AUTH-001   | Request-dependent Prisma filter on a related resource has no supported principal constraint | MEDIUM / MEDIUM       | Middleware and post-query guards may authorize access                         |
| REAPER-TENANT-001 | Route reaches a related tenant resource without supported tenant constraint                 | MEDIUM / MEDIUM       | Source analysis does not prove database RLS                                   |
| REAPER-RLS-001    | PUBLIC/anon/authenticated table grant and RLS disabled                                      | HIGH / MEDIUM         | Schema exposure and application paths need independent verification           |
| REAPER-RLS-002    | RLS enabled and no policies                                                                 | INFO / MEDIUM         | Default deny, not default allow; bypass roles remain relevant                 |
| REAPER-RLS-003    | Broad-role permissive policy has constant TRUE USING or CHECK                               | MEDIUM / MEDIUM       | Restrictive policies, commands and grants affect effective access             |
| REAPER-PRIV-001   | Broad role has TRUNCATE, TRIGGER or REFERENCES                                              | HIGH / MEDIUM         | Review intended privilege; owner privileges alone are not flagged             |

Role membership is collected only as role attributes in this milestone; inheritance is not expanded. Source and catalog results are not combined into an exploitability proof. No score is computed because coverage is too incomplete to justify one.
