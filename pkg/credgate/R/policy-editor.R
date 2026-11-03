#' Policy editor for InfoSec and compliance
#'
#' A Shiny app to edit a credgate policy without writing YAML: the model
#' endpoints and their tiers, the rules in order (first match wins), the
#' default action. Every edit is checked at once with the same strict rules
#' the proxy and the Python package use, and an invalid policy cannot be
#' saved. **Try it** shows what the policy would do with a sample text sent
#' to an endpoint: allowed or blocked, and for each identifier the action and
#' the rule that decided it. **Changes** shows what changed since the last
#' save and the change log. Saving raises the revision and records who
#' changed what, when and why (see [policy_write()]).
#'
#' Run it locally (it opens in the browser), or on Shiny Server with an
#' `app.R` of one line: `credgate::policy_editor("/srv/policies/bank.yaml")`.
#' There, the editor records Shiny Server's signed-in user when there is one.
#' Needs the shiny and bslib packages.
#'
#' @param path The policy file (YAML). A new file starts from the bank
#'   example policy.
#' @param user Who is editing, for the change log; defaults to the signed-in
#'   Shiny user or the operating-system user.
#' @return A Shiny app; printing it (or [shiny::runApp()]) runs it.
#' @export
#' @examples
#' if (interactive()) {
#'   policy_editor(file.path(tempdir(), "bank.yaml"))
#' }
policy_editor <- function(path, user = NULL) {
  check_installed("shiny")
  check_installed("bslib")
  stopifnot(rlang::is_string(path))
  shiny::shinyApp(policy_editor_ui(path), policy_editor_server(path, user), onStart = function() {
    shiny::onStop(writable_temp_assets)
  })
}

policy_template <- function() {
  yaml::read_yaml(system.file("policies", "bank-default.yaml", package = "credgate"))
}

policy_read_file <- function(path) {
  if (file.exists(path)) {
    yaml::yaml.load(paste(read_utf8_lines(path), collapse = "\n"))
  } else {
    policy_template()
  }
}

# Validation: the same strict parse the proxy relies on; NULL when valid.
policy_problem <- function(x, dir = getwd()) {
  tryCatch(
    {
      parse_policy(x, dir)
      NULL
    },
    error = function(e) conditionMessage(e)
  )
}

policy_editor_ui <- function(path) {
  tiers <- c("local", "internal", "frontier")
  actions <- c("allow", "redact", "tokenise", "block")
  asset <- function(f) system.file("policy-editor", f, package = "credgate")
  section <- function(x) shiny::div(class = "cg-section", x)
  page <- bslib::page_sidebar(
    title = shiny::div(
      class = "cg-brand",
      shiny::HTML(paste0(
        '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" ',
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">',
        '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'
      )),
      shiny::span(class = "cg-name", "credgate"),
      shiny::span(class = "cg-sub", "Policy editor"),
      shiny::uiOutput("header_status", class = "cg-header-status"),
      bslib::input_dark_mode(id = "dark_mode")
    ),
    window_title = "credgate policy editor",
    theme = bslib::bs_theme(
      version = 5, primary = "#0e5a6b", "border-radius" = "8px",
      base_font = bslib::font_collection("system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"),
      code_font = bslib::font_collection("ui-monospace", "SFMono-Regular", "Menlo", "monospace")
    ),
    fillable = FALSE,
    sidebar = bslib::sidebar(
      width = 320,
      shiny::tags$head(shiny::includeCSS(asset("editor.css")), shiny::includeScript(asset("editor.js"))),
      section("Policy file"),
      shiny::div(class = "cg-file", path),
      shiny::uiOutput("status"),
      section("Policy"),
      shiny::textInput("policy_id", tip("Policy id", "A short name for this policy. It is recorded with every decision in the audit log, together with the revision.")),
      shiny::textAreaInput("description", "Description", rows = 3),
      shiny::selectInput("default_action", tip("When no rule matches", "What happens to an identifier that no rule matches. block is the safest: anything not explicitly allowed stops the request."), actions),
      shiny::numericInput("min_confidence", tip("Minimum confidence (0-1)", "Matches scored below this are ignored. For example, an order number that passes the Aadhaar checksum by chance scores about 0.42."), 0.5, min = 0, max = 1, step = 0.05),
      section("Save"),
      shiny::textInput("user", tip("Your name", "Recorded in the change log with every save. On Shiny Server it is filled in from the signed-in user.")),
      shiny::textInput("note", tip("Why this change", "A few words for the change log, such as a ticket number or an approval. Reviewers and auditors read it."), placeholder = "e.g. new GPU endpoint approved"),
      bslib::tooltip(shiny::actionButton("save", "Save new revision", class = "btn-primary"), "Writes the policy with its revision raised by one and adds an entry to the change log. Only possible when the draft is valid and has changes."),
      bslib::tooltip(shiny::actionButton("reload", "Discard changes", class = "btn-link btn-sm"), "Throws away the draft and reloads the saved file.")
    ),
    shiny::uiOutput("stats", class = "cg-stats"),
    bslib::navset_card_tab(
      bslib::nav_panel(
        "Endpoints",
        shiny::p(class = "cg-lede", "The model endpoints requests may go to. An endpoint not listed here receives nothing. Click a row to edit it."),
        shiny::uiOutput("endpoints"),
        shiny::div(
          class = "cg-form",
          shiny::uiOutput("ep_form_title", inline = TRUE),
          bslib::layout_columns(
            shiny::selectInput("ep_pick", tip("Endpoint", "Pick an endpoint to edit, or (new endpoint) to add one. You can also click a row in the table."), NULL),
            shiny::textInput("ep_name", tip("Name", "How people and rules refer to this endpoint, e.g. claude or vllm-gpu. Renaming it updates the rules that name it.")),
            shiny::selectInput("ep_tier", tip("Tier", "Where the data ends up. local: the analyst's own machine. internal: models the organisation runs itself. frontier: external providers, also when reached through its own gateway."), tiers),
            shiny::textInput("ep_provider", tip("Provider", "Who runs the model (ollama, vllm, anthropic...). For the record only; rules do not use it."), placeholder = "vllm, anthropic..."),
            col_widths = c(3, 3, 3, 3)
          ),
          bslib::layout_columns(
            shiny::textInput("ep_url", tip("URL", "The OpenAI-compatible base URL the proxy forwards requests to."), placeholder = "https://llm.bank.internal/v1"),
            shiny::textInput("ep_description", tip("Description", "Why this endpoint exists or what it may be used for. Kept in the policy file.")),
            shiny::div(style = "padding-top: 1.9rem", shiny::checkboxInput("ep_blocked", tip("Blocked", "Keeps the endpoint on record but refuses every request to it, e.g. a tool not yet approved."))),
            col_widths = c(5, 5, 2)
          ),
          shiny::div(
            class = "cg-actions",
            bslib::tooltip(shiny::actionButton("ep_apply", "Apply to draft", class = "btn-primary btn-sm"), "Adds or updates the endpoint in the draft. Nothing is written until you save."),
            bslib::tooltip(shiny::actionButton("ep_delete", "Remove endpoint", class = "btn-outline-danger btn-sm"), "Removes the endpoint from the draft. Not allowed while a rule names it.")
          )
        )
      ),
      bslib::nav_panel(
        "Rules",
        shiny::p(class = "cg-lede", "Checked in order for each identifier found: the first rule that matches decides what happens to it. Any block stops the whole request. Click a rule to edit or move it."),
        shiny::uiOutput("rules"),
        shiny::div(
          class = "cg-form",
          shiny::uiOutput("rule_form_title", inline = TRUE),
          bslib::layout_columns(
            shiny::selectInput("rule_pick", tip("Rule", "Pick a rule to edit, or (new rule) to add one at the end. You can also click a rule in the list."), NULL),
            shiny::textInput("rule_id", tip("Rule id", "A short unique name. Decisions and the audit log name the rule that decided each action.")),
            shiny::selectInput("rule_action", tip("Action", "allow: sent as is. redact: replaced by a label like [PAN]. tokenise: replaced by a reversible token kept in the vault. block: the whole request is refused."), actions),
            shiny::textInput("rule_description", tip("Description", "Why the rule exists, e.g. the regulation or approval behind it. Kept in the policy file.")),
            col_widths = c(3, 3, 2, 4)
          ),
          bslib::layout_columns(
            shiny::selectizeInput("rule_destinations", tip("Endpoints", "Only requests to these endpoints. Empty: any endpoint."), NULL, multiple = TRUE),
            shiny::selectizeInput("rule_tiers", tip("Tiers", "Only requests to endpoints of these tiers. Empty: any tier."), tiers, multiple = TRUE),
            shiny::selectizeInput("rule_classes", tip("Data classes", "Groups of identifier types, e.g. financial covers card numbers and bank accounts. Empty: any class."), NULL, multiple = TRUE),
            col_widths = c(4, 4, 4)
          ),
          bslib::layout_columns(
            shiny::selectizeInput("rule_types", tip("Identifier types", "Particular identifiers, e.g. pan, aadhaar, card_cvv. Empty: any type."), NULL, multiple = TRUE),
            shiny::selectizeInput("rule_all_of", tip("Only when all of these are present", "The rule applies only if the request contains every one of these types, e.g. card, card_cvv and card_expiry together."), NULL, multiple = TRUE),
            col_widths = c(6, 6)
          ),
          shiny::p(class = "cg-hint", "Empty fields match everything. Conditions combine with AND."),
          shiny::div(
            class = "cg-actions",
            bslib::tooltip(shiny::actionButton("rule_apply", "Apply to draft", class = "btn-primary btn-sm"), "Adds the rule at the end, or updates the selected one. Nothing is written until you save."),
            bslib::tooltip(shiny::actionButton("rule_up", "\u2191 Move up", class = "btn-outline-secondary btn-sm"), "Checked earlier. The first matching rule decides, so order changes outcomes."),
            bslib::tooltip(shiny::actionButton("rule_down", "\u2193 Move down", class = "btn-outline-secondary btn-sm"), "Checked later. Use Try it to see the effect."),
            bslib::tooltip(shiny::actionButton("rule_delete", "Remove rule", class = "btn-outline-danger btn-sm"), "Removes the selected rule from the draft.")
          )
        )
      ),
      bslib::nav_panel(
        "Try it",
        shiny::p(class = "cg-lede", "What the draft policy (before saving) does with a request. Use synthetic data only."),
        bslib::layout_columns(
          shiny::div(
            shiny::textAreaInput(
              "try_text", "Request text", width = "100%", rows = 6,
              value = paste(
                "Customer PAN ABCPE1234F, mobile +91 98765 43210.",
                "Card 4111 1111 1111 1111, CVV 123, expiry 08/29."
              )
            ),
            shiny::selectInput("try_endpoint", tip("Sent to", "The endpoint the request would go to. Its tier and name decide which rules apply."), NULL, width = "100%")
          ),
          shiny::div(
            shiny::uiOutput("try_result"),
            shiny::uiOutput("try_output")
          ),
          col_widths = c(5, 7)
        ),
        shiny::uiOutput("try_matches")
      ),
      bslib::nav_panel(
        "Changes",
        shiny::h6(class = "cg-section", "Since the last save"),
        shiny::uiOutput("pending"),
        shiny::h6(class = "cg-section", "Change log"),
        shiny::uiOutput("history")
      )
    )
  )  # Called per page load, so a reload works on read-only installs (see below).
  function(req) {
    writable_temp_assets()
    page
  }
}


policy_editor_server <- function(path, user = NULL) {
  function(input, output, session) {
    saved <- shiny::reactiveVal(policy_read_file(path))
    policy <- shiny::reactiveVal(policy_read_file(path))
    saved_at <- shiny::reactiveVal(0)
    detectors <- cg_detectors()

    who <- user %||% session$user %||% Sys.info()[["user"]]
    shiny::updateTextInput(session, "user", value = who)

    load_fields <- function(x) {
      shiny::updateTextInput(session, "policy_id", value = x$id %||% "")
      shiny::updateTextAreaInput(session, "description", value = x$description %||% "")
      shiny::updateSelectInput(session, "default_action", selected = x$default_action)
      shiny::updateNumericInput(session, "min_confidence", value = x$min_confidence %||% 0)
    }
    load_fields(shiny::isolate(policy()))

    edit <- function(f) policy(f(policy()))

    shiny::observeEvent(input$policy_id, edit(function(x) {
      x$id <- input$policy_id
      x
    }), ignoreInit = TRUE)
    shiny::observeEvent(input$description, edit(function(x) {
      x$description <- if (nzchar(input$description)) input$description
      x
    }), ignoreInit = TRUE)
    shiny::observeEvent(input$default_action, edit(function(x) {
      x$default_action <- input$default_action
      x
    }), ignoreInit = TRUE)
    shiny::observeEvent(input$min_confidence, edit(function(x) {
      if (!(is.null(x$min_confidence) && identical(as.numeric(input$min_confidence), 0))) {
        x$min_confidence <- input$min_confidence
      }
      x
    }), ignoreInit = TRUE)

    problem <- shiny::reactive(policy_problem(policy(), dirname(path)))
    changes <- shiny::reactive({
      x <- policy()
      x$revision <- saved()$revision
      policy_diff(saved(), x)
    })

    output$status <- shiny::renderUI({
      n <- length(changes())
      if (!is.null(problem())) {
        shiny::div(class = "cg-status bad", shiny::strong("Not valid - cannot be saved. "), problem())
      } else if (n > 0) {
        shiny::div(class = "cg-status pending", shiny::strong("Valid draft. "), sprintf(
          "%d unsaved change%s to revision %s.", n, if (n == 1) "" else "s", saved()$revision
        ))
      } else {
        shiny::div(class = "cg-status ok", shiny::strong("Saved. "), sprintf("Revision %s, no changes.", saved()$revision))
      }
    })
    output$header_status <- shiny::renderUI({
      shiny::tagList(
        cg_badge(policy()$id %||% "(no id)", "neutral"),
        cg_badge(sprintf("revision %s", saved()$revision), "neutral"),
        if (!is.null(problem())) cg_badge("not valid", "block")
        else if (length(changes())) cg_badge("unsaved changes", "redact")
        else cg_badge("saved", "allow")
      )
    })
    output$stats <- shiny::renderUI({
      d <- policy()$destinations %||% list()
      blocked <- sum(vapply(d, function(e) isTRUE(e$blocked), logical(1)))
      tiers <- table(factor(vapply(d, function(e) e$tier %||% "", ""), c("local", "internal", "frontier")))
      n <- length(changes())
      stat <- function(label, value, note, kind = "") {
        shiny::div(class = paste("cg-stat", kind), shiny::div(class = "label", label),
                   shiny::div(class = "value", value), shiny::div(class = "note", note))
      }
      shiny::tagList(
        stat("Endpoints", length(d), sprintf("%d local \u00b7 %d internal \u00b7 %d frontier%s",
          tiers[["local"]], tiers[["internal"]], tiers[["frontier"]],
          if (blocked) sprintf(" \u00b7 %d blocked", blocked) else "")),
        stat("Rules", length(policy()$rules), sprintf("then %s by default", policy()$default_action %||% "?")),
        stat("Unsaved changes", n, if (n) "review them under Changes" else "draft matches the file",
             if (n) "warn" else ""),
        if (is.null(problem())) stat("Status", "Valid", "the proxy would load it", "ok")
        else stat("Status", "Invalid", "fix before saving", "bad")
      )
    })

    # --- endpoints ---------------------------------------------------------
    endpoint_names <- shiny::reactive(names(policy()$destinations %||% list()))
    shiny::observe({
      names <- endpoint_names()
      keep <- shiny::isolate(input$ep_pick)
      shiny::updateSelectInput(session, "ep_pick", choices = c("(new endpoint)" = "", names),
                               selected = if (!is.null(keep) && keep %in% names) keep else "")
      shiny::updateSelectizeInput(session, "rule_destinations", choices = names,
                                  selected = shiny::isolate(input$rule_destinations))
      to <- shiny::isolate(input$try_endpoint)
      shiny::updateSelectInput(session, "try_endpoint", choices = names,
                               selected = if (!is.null(to) && to %in% names) to else names[1])
    })
    output$endpoints <- shiny::renderUI({
      d <- policy()$destinations %||% list()
      if (length(d) == 0) {
        return(shiny::div(class = "cg-empty", "No endpoints yet: every request would be refused."))
      }
      pick <- input$ep_pick %||% ""
      rows <- lapply(names(d), function(name) {
        e <- d[[name]]
        shiny::tags$tr(
          `data-pick` = name, `data-target` = "ep_pick",
          class = paste(if (identical(name, pick)) "selected", if (isTRUE(e$blocked)) "is-blocked"),
          shiny::tags$td(shiny::div(class = "name", shiny::strong(name)),
                         if (!is.null(e$description)) shiny::div(class = "desc", e$description)),
          shiny::tags$td(cg_badge(e$tier %||% "?", e$tier %||% "neutral")),
          shiny::tags$td(e$provider %||% ""),
          shiny::tags$td(class = "mono", e$url %||% ""),
          shiny::tags$td(if (isTRUE(e$blocked)) cg_badge("blocked", "blocked") else cg_badge("open", "allow"))
        )
      })
      shiny::div(class = "cg-scroll", shiny::tags$table(
        class = "cg-table",
        shiny::tags$thead(shiny::tags$tr(lapply(c("Endpoint", "Tier", "Provider", "URL", "Requests"), shiny::tags$th))),
        shiny::tags$tbody(rows)
      ))
    })
    output$ep_form_title <- shiny::renderUI({
      shiny::h6(if (nzchar(input$ep_pick %||% "")) paste("Edit", input$ep_pick) else "Add an endpoint")
    })
    shiny::observeEvent(input$ep_pick, {
      e <- if (nzchar(input$ep_pick)) policy()$destinations[[input$ep_pick]] else list(tier = "local")
      shiny::updateTextInput(session, "ep_name", value = input$ep_pick)
      shiny::updateSelectInput(session, "ep_tier", selected = e$tier)
      shiny::updateTextInput(session, "ep_provider", value = e$provider %||% "")
      shiny::updateTextInput(session, "ep_url", value = e$url %||% "")
      shiny::updateTextInput(session, "ep_description", value = e$description %||% "")
      shiny::updateCheckboxInput(session, "ep_blocked", value = isTRUE(e$blocked))
    })
    shiny::observeEvent(input$ep_apply, {
      name <- trimws(input$ep_name)
      if (!nzchar(name)) {
        shiny::showNotification("An endpoint needs a name.", type = "error")
        return()
      }
      old <- input$ep_pick
      edit(function(x) {
        entry <- list(tier = input$ep_tier)
        for (f in c("provider", "url", "description")) {
          v <- trimws(input[[paste0("ep_", f)]])
          if (nzchar(v)) entry[[f]] <- v
        }
        if (isTRUE(input$ep_blocked)) entry$blocked <- TRUE
        d <- x$destinations %||% list()
        if (nzchar(old) && old != name) {
          d[[old]] <- NULL
          x$rules <- lapply(x$rules, rename_destination, old, name)
        }
        d[[name]] <- entry
        x$destinations <- d
        x
      })
      shiny::updateSelectInput(session, "ep_pick", selected = name)
    })
    shiny::observeEvent(input$ep_delete, {
      name <- input$ep_pick
      if (!nzchar(name)) {
        return()
      }
      used <- vapply(policy()$rules, function(r) name %in% unlist(r$when$destinations), logical(1))
      if (any(used)) {
        shiny::showNotification(sprintf(
          "Rule(s) %s name this endpoint; change them first.",
          paste(vapply(policy()$rules[used], `[[`, "", "id"), collapse = ", ")
        ), type = "error")
        return()
      }
      edit(function(x) {
        x$destinations[[name]] <- NULL
        x
      })
    })

    # --- rules -----------------------------------------------------------------
    rule_ids <- shiny::reactive(vapply(policy()$rules %||% list(), function(r) r$id %||% "", ""))
    shiny::observe({
      ids <- rule_ids()
      keep <- shiny::isolate(input$rule_pick)
      shiny::updateSelectInput(session, "rule_pick", choices = c("(new rule)" = "", ids),
                               selected = if (!is.null(keep) && keep %in% ids) keep else "")
    })
    shiny::updateSelectizeInput(session, "rule_types", choices = detectors$id)
    shiny::updateSelectizeInput(session, "rule_all_of", choices = detectors$id)
    shiny::updateSelectizeInput(session, "rule_classes", choices = sort(unique(c(
      "identity_strong", "financial", "sensitive_auth", "health", "contact", "personal", "quasi",
      detectors$class
    ))))
    output$rules <- shiny::renderUI({
      rules <- policy()$rules %||% list()
      pick <- input$rule_pick %||% ""
      labels <- c(destinations = "Endpoints", tiers = "Tiers", classes = "Classes", types = "Types", all_of = "All of")
      cards <- lapply(seq_along(rules), function(i) {
        r <- rules[[i]]
        when <- r$when %||% list()
        keys <- intersect(names(labels), names(when))
        shiny::div(
          class = paste("cg-rule", if (identical(r$id, pick)) "selected"),
          `data-pick` = r$id, `data-target` = "rule_pick",
          shiny::div(class = "order", i),
          shiny::div(
            shiny::div(class = "id", r$id),
            if (!is.null(r$description)) shiny::div(class = "desc", r$description),
            shiny::div(
              class = "when",
              if (length(keys) == 0) shiny::span(class = "part", "Every identifier")
              else lapply(keys, function(k) shiny::span(
                class = "part", shiny::span(class = "key", labels[[k]]),
                lapply(unlist(when[[k]]), function(v) shiny::span(class = "cg-chip", v))
              ))
            )
          ),
          cg_badge(r$action %||% "?", r$action %||% "neutral")
        )
      })
      shiny::div(
        class = "cg-rules", cards,
        shiny::div(
          class = "cg-rule cg-rule-default",
          shiny::div(class = "order", "\u2013"),
          shiny::div(shiny::div(class = "id", "Otherwise"),
                     shiny::div(class = "desc", "When no rule matches (set in the sidebar)")),
          cg_badge(policy()$default_action %||% "?", policy()$default_action %||% "neutral")
        )
      )
    })
    output$rule_form_title <- shiny::renderUI({
      shiny::h6(if (nzchar(input$rule_pick %||% "")) paste("Edit rule", input$rule_pick) else "Add a rule (at the end)")
    })
    shiny::observeEvent(input$rule_pick, {
      ids <- rule_ids()
      r <- if (nzchar(input$rule_pick)) policy()$rules[[match(input$rule_pick, ids)]] else list(action = "redact")
      shiny::updateTextInput(session, "rule_id", value = input$rule_pick)
      shiny::updateSelectInput(session, "rule_action", selected = r$action)
      shiny::updateTextInput(session, "rule_description", value = r$description %||% "")
      for (k in c("destinations", "tiers", "types", "classes", "all_of")) {
        shiny::updateSelectizeInput(session, paste0("rule_", k), selected = unlist(r$when[[k]]) %||% character())
      }
    })
    shiny::observeEvent(input$rule_apply, {
      id <- trimws(input$rule_id)
      if (!nzchar(id)) {
        shiny::showNotification("A rule needs an id.", type = "error")
        return()
      }
      old <- input$rule_pick
      when <- list()
      for (k in c("destinations", "tiers", "types", "classes", "all_of")) {
        v <- input[[paste0("rule_", k)]]
        if (length(v)) when[[k]] <- as.list(v)
      }
      rule <- list(id = id)
      if (nzchar(trimws(input$rule_description))) rule$description <- trimws(input$rule_description)
      if (length(when)) rule$when <- when
      rule$action <- input$rule_action
      edit(function(x) {
        ids <- vapply(x$rules %||% list(), function(r) r$id, "")
        at <- if (nzchar(old)) match(old, ids) else length(ids) + 1L
        if (is.null(x$rules)) x$rules <- list()
        x$rules[[at]] <- rule
        x
      })
      shiny::updateSelectInput(session, "rule_pick", selected = id)
    })
    move <- function(by) {
      ids <- rule_ids()
      at <- match(input$rule_pick, ids)
      to <- at + by
      if (is.na(at) || to < 1 || to > length(ids)) {
        return()
      }
      edit(function(x) {
        x$rules[c(at, to)] <- x$rules[c(to, at)]
        x
      })
    }
    shiny::observeEvent(input$rule_up, move(-1L))
    shiny::observeEvent(input$rule_down, move(1L))
    shiny::observeEvent(input$rule_delete, {
      at <- match(input$rule_pick, rule_ids())
      if (is.na(at)) {
        return()
      }
      edit(function(x) {
        x$rules[[at]] <- NULL
        x
      })
    })

    # --- try it ------------------------------------------------------------------
    decision <- shiny::reactive({
      shiny::req(is.null(problem()), input$try_endpoint, nzchar(input$try_text))
      policy_decide(cg_policy(policy(), dirname(path)), input$try_text, input$try_endpoint)
    })
    output$try_result <- shiny::renderUI({
      if (!is.null(problem())) {
        return(shiny::div(class = "cg-verdict neutral", shiny::div(
          shiny::div(class = "big", "Fix the policy first"), shiny::div(class = "small", problem())
        )))
      }
      d <- decision()
      m <- d$matches
      counts <- if (nrow(m)) paste(sprintf("%d %s", as.vector(table(m$action)), names(table(m$action))), collapse = " \u00b7 ")
      if (isTRUE(d$allowed)) {
        shiny::div(class = "cg-verdict ok", shiny::div(
          shiny::div(class = "big", sprintf("\u2713 Sent to %s", d$destination)),
          shiny::div(class = "small", sprintf("%s tier. %s", d$tier,
            if (nrow(m)) sprintf("%d identifier(s) found: %s.", nrow(m), counts) else "No identifiers found."))
        ))
      } else {
        shiny::div(class = "cg-verdict bad", shiny::div(
          shiny::div(class = "big", sprintf("\u26d4 Blocked - nothing reaches %s", d$destination)),
          shiny::div(class = "small", sprintf("%s tier. Blocked by rule %s.", d$tier, paste(d$blocked_by, collapse = ", ")))
        ))
      }
    })
    output$try_output <- shiny::renderUI({
      d <- decision()
      shiny::req(isTRUE(d$allowed))
      text <- tryCatch(
        policy_apply(cg_policy(policy(), dirname(path)), input$try_text, input$try_endpoint)$text,
        error = function(e) NULL
      )
      shiny::tagList(
        shiny::div(class = "cg-out-label", "What the model receives"),
        shiny::div(class = "cg-out", text %||% "(tokenising needs a vault; the proxy uses one)")
      )
    })
    output$try_matches <- shiny::renderUI({
      m <- decision()$matches
      if (nrow(m) == 0) {
        return(NULL)
      }
      shiny::div(class = "cg-scroll", shiny::tags$table(
        class = "cg-table",
        shiny::tags$thead(shiny::tags$tr(lapply(c("Identifier", "Found (masked)", "Action", "Decided by"), shiny::tags$th))),
        shiny::tags$tbody(lapply(seq_len(nrow(m)), function(i) shiny::tags$tr(
          shiny::tags$td(shiny::strong(m$type[i]), shiny::div(class = "desc", m$class[i])),
          shiny::tags$td(class = "mono", mask_value(m$value[i], m$class[i])),
          shiny::tags$td(cg_badge(m$action[i], m$action[i])),
          shiny::tags$td(if (is.na(m$rule[i]) || !nzchar(m$rule[i])) "default action" else m$rule[i])
        )))
      ))
    })

    # --- changes and saving --------------------------------------------------------
    output$pending <- shiny::renderUI({
      ch <- changes()
      if (length(ch) == 0) {
        return(shiny::div(class = "cg-empty", "No unsaved changes: the draft matches the saved file."))
      }
      kind <- ifelse(grepl(" added", ch), "add", ifelse(grepl(" removed$", ch), "del", "mod"))
      shiny::tags$ul(class = "cg-diff", lapply(seq_along(ch), function(i) shiny::tags$li(class = kind[i], ch[i])))
    })
    history <- shiny::reactive({
      saved_at()
      policy_changes(path)
    })
    output$history <- shiny::renderUI({
      h <- history()
      alert <- if (!isTRUE(attr(h, "intact"))) {
        shiny::div(class = "cg-alert", "The change log was altered: entries were edited or removed after they were written.")
      }
      if (nrow(h) == 0) {
        return(shiny::tagList(alert, shiny::div(class = "cg-empty", "No saves yet. The first save starts the change log.")))
      }
      h <- h[rev(seq_len(nrow(h))), ]
      shiny::tagList(alert, shiny::div(class = "cg-timeline", lapply(seq_len(nrow(h)), function(i) shiny::div(
        class = "cg-entry",
        shiny::div(class = "head", shiny::span(class = "rev", sprintf("Revision %d", h$revision[i])),
                   shiny::span(class = "meta", sprintf(" \u00b7 %s \u00b7 %s", h$user[i], sub("T", " ", h$time[i])))),
        if (nzchar(h$note[i])) shiny::div(class = "note", h$note[i]),
        shiny::tags$ul(lapply(h$changes[[i]], shiny::tags$li))
      ))))
    })
    shiny::observe({
      ok <- is.null(problem()) && length(changes()) > 0
      shiny::updateActionButton(session, "save", disabled = !ok)
    })
    shiny::observeEvent(input$save, {
      if (!is.null(problem()) || length(changes()) == 0) {
        return()
      }
      if (!nzchar(trimws(input$user))) {
        shiny::showNotification("Enter your name for the change log.", type = "error")
        return()
      }
      x <- policy()
      x$revision <- saved()$revision
      written <- tryCatch(
        policy_write(x, path, user = trimws(input$user), note = trimws(input$note)),
        error = function(e) {
          shiny::showNotification(paste("Not saved:", conditionMessage(e)), type = "error")
          NULL
        }
      )
      if (!is.null(written)) {
        saved(written)
        policy(written)
        saved_at(saved_at() + 1)
        shiny::updateTextInput(session, "note", value = "")
        shiny::showNotification(sprintf("Saved revision %d.", written$revision), type = "message")
      }
    })
    shiny::observeEvent(input$reload, {
      x <- policy_read_file(path)
      saved(x)
      policy(x)
      load_fields(x)
    })
  }
}

# Shiny and bslib copy their scripts into tempdir() on every page load. Copies
# from a read-only library (Nix, a locked site library) stay read-only, so the
# next page load cannot overwrite them and fails, and R cannot remove its
# temporary directory at exit; make them writable.
writable_temp_assets <- function() {
  paths <- list.files(tempdir(), recursive = TRUE, full.names = TRUE, include.dirs = TRUE)
  locked <- paths[file.access(paths, 2) != 0]
  if (length(locked) == 0) {
    return(invisible())
  }
  Sys.chmod(locked, ifelse(dir.exists(locked), "0755", "0644"), use_umask = FALSE)
}

# A label with an info icon that explains it on hover or focus.
tip <- function(label, text) {
  shiny::span(label, bslib::tooltip(
    shiny::span(class = "cg-tip", tabindex = "0", `aria-label` = text, "i"), text, placement = "right"
  ))
}

badge_help <- c(
  local = "On the analyst's own machine",
  internal = "Models the organisation runs itself",
  frontier = "External providers: the data leaves the organisation",
  allow = "Sent as is",
  redact = "Replaced by a label such as [PAN]",
  tokenise = "Replaced by a reversible token kept in the vault",
  block = "The whole request is refused",
  blocked = "Every request to this endpoint is refused"
)

cg_badge <- function(text, kind) {
  help <- if (kind %in% names(badge_help)) badge_help[[kind]]
  shiny::span(class = paste0("cg-badge cg-", kind), title = help, text)
}

rename_destination <- function(rule, old, new) {
  d <- unlist(rule$when$destinations)
  if (old %in% d) {
    d[d == old] <- new
    rule$when$destinations <- as.list(d)
  }
  rule
}
