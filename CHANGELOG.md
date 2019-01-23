# BOSS OIDC Django Authentication Plugin

* v1.2.2 : Cleanup of packaging and added unit tests
* v1.2.1 : Merged in PR #28 to address missing migrations directory from the installed library
* v1.2 : Merged in PRs and addressed issues
  * Merged in PR #14 (Adding support for client secret)
  * Merged in PR #17 (Fixed issue #16, improvement of registration of admin extension)
  * Merged in PR #20 (Fixed issue #19, providing client roles in `LOAD_USER_ROLES_FUNCTION`)
  * Merged in PR #22 (Fixed issue #21, committing migration files)
  * Merged in PR #23 (Fixed issue #6, dynamically figure out max username length)
  * Merged in PR #26 / #26 (Enforces the JWT standard for rejecting tokens without
    the appropriate audience)
