#' Read a users file
#'
#' The users file says who may use the credgate app, in which role, and the
#' limits admins set (see the spec, "Users file"). It is changed only from the
#' server's command line (`credgate users ...`, in the Python package); the
#' app reads it with this function. A name that is not in the file, or is
#' inactive, has no access.
#'
#' @param x A users file, or its contents as a list.
#' @return A list with `users` (a data frame: `name`, `role`, `active`) and
#'   `settings` (`key_max_days`, `activity_days`, `activity_max`).
#' @export
#' @examples
#' users <- cg_users(list(
#'   kind = "credgate-users", version = 1,
#'   users = list(priya = list(role = "admin"), arjun = list(role = "user", active = FALSE))
#' ))
#' users$users
cg_users <- function(x) {
  name <- if (rlang::is_string(x)) x else "users"
  data <- if (rlang::is_string(x)) yaml::yaml.load(paste(read_utf8_lines(x), collapse = "\n")) else x
  tryCatch(parse_users(data), error = function(e) {
    rlang::abort(paste0(name, ": ", conditionMessage(e)), class = "credgate_users_error", call = NULL)
  })
}

user_roles <- c("admin", "auditor", "user")
user_settings <- list(
  key_max_days = c(90, 30, 180), # default, lowest, highest
  activity_days = c(7, 1, 90),
  activity_max = c(100, 1, 1000)
)

parse_users <- function(data) {
  fail <- function(...) stop(..., call. = FALSE)
  if (!is.list(data) || !identical(data$kind, "credgate-users")) {
    fail("not a users file: `kind` must be `credgate-users`.")
  }
  unknown <- setdiff(names(data), c("kind", "version", "settings", "users"))
  if (length(unknown)) fail("unknown field(s): ", paste(sort(unknown), collapse = ", "), ".")
  if (!identical(as.numeric(data$version), 1)) fail("`version` must be 1.")
  settings <- lapply(user_settings, `[[`, 1)
  for (k in names(data$settings)) {
    if (!k %in% names(user_settings)) fail("unknown setting `", k, "`.")
    v <- data$settings[[k]]
    r <- user_settings[[k]]
    if (!rlang::is_scalar_integerish(v) || is.logical(v) || v < r[2] || v > r[3]) {
      fail("setting `", k, "` must be a whole number from ", r[2], " to ", r[3], ".")
    }
    settings[[k]] <- as.integer(v)
  }
  settings <- lapply(settings, as.integer)
  users <- data$users %||% list()
  if (!is.list(users) || (length(users) && is.null(names(users)))) fail("`users` must map names to roles.")
  rows <- lapply(names(users), function(n) {
    u <- users[[n]]
    if (!grepl("^[A-Za-z0-9._@-]{1,100}$", n)) {
      fail("user name '", n, "': letters, digits, '.', '_', '@' and '-' only.")
    }
    if (!is.list(u)) fail("user '", n, "' needs a `role`.")
    unknown <- setdiff(names(u), c("role", "active"))
    if (length(unknown)) fail("user '", n, "': unknown field(s): ", paste(sort(unknown), collapse = ", "), ".")
    if (!rlang::is_string(u$role) || !u$role %in% user_roles) {
      fail("user '", n, "': role must be one of ", paste(user_roles, collapse = ", "), ".")
    }
    active <- u$active %||% TRUE
    if (!rlang::is_bool(active)) fail("user '", n, "': `active` must be true or false.")
    data.frame(name = n, role = u$role, active = active, stringsAsFactors = FALSE)
  })
  list(
    users = do.call(rbind, c(list(data.frame(name = character(), role = character(), active = logical())), rows)),
    settings = settings
  )
}

# The role of an active user, or NULL (no access).
user_role <- function(users, name) {
  if (is.null(name) || !nzchar(name)) {
    return(NULL)
  }
  u <- users$users[users$users$name == name & users$users$active, , drop = FALSE]
  if (nrow(u) == 1) u$role else NULL
}
