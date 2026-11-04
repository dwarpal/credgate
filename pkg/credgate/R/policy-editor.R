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
#'   Shiny user or the operating-system user. With `users`, also who is
#'   signed in, for their role (on a server the signed-in user is used).
#' @param users A users file (see [cg_users()]): who may use the app and in
#'   which role. Admins see and change everything; auditors see the policy,
#'   tests and change log but change nothing; users try the saved policy,
#'   see test results and try detectors. Anyone not in the file, or
#'   inactive, has no access. Without a users file everyone is an admin.
#' @param keys The proxy's keys file (see [proxy_add_user()]): everyone
#'   manages their own key under **My key** (1, 3 or 6 months, up to the
#'   users file's `key_max_days`), and admins manage everyone's under
#'   **Users**; each change is recorded in the access log ([proxy_access()]).
#' @return A Shiny app; printing it (or [shiny::runApp()]) runs it.
#' @export
#' @examples
#' if (interactive()) {
#'   policy_editor(file.path(tempdir(), "bank.yaml"))
#' }
policy_editor <- function(path, user = NULL, users = NULL, keys = NULL) {
  check_installed("shiny")
  check_installed("bslib")
  stopifnot(rlang::is_string(path), is.null(users) || rlang::is_string(users), is.null(keys) || rlang::is_string(keys))
  shiny::shinyApp(policy_editor_ui(path), policy_editor_server(path, user, users, keys), onStart = function() {
    shiny::onStop(writable_temp_assets)
  })
}

# The tabs each role sees, and the role of a signed-in name (NULL: no
# access). Without a users file everyone is an admin, as before roles.
editor_tabs <- list(
  admin = c("Endpoints", "Rules", "Try it", "Tests", "Detectors", "My key", "Users", "Changes"),
  auditor = c("Endpoints", "Rules", "Tests", "My key", "Users", "Changes"),
  user = c("Try it", "Tests", "Detectors", "My key", "Changes")
)
key_durations <- c("1 month" = 30L, "3 months" = 90L, "6 months" = 180L)

editor_role <- function(users, name) {
  if (is.null(users)) {
    return("admin")
  }
  u <- tryCatch(cg_users(users), error = function(e) NULL)  # an invalid file lets no one in
  if (is.null(u)) NULL else user_role(u, name)
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
      shiny::uiOutput("role_note"),
      shiny::div(
      id = "cg-admin-controls",
      section("Policy"),
      shiny::textInput("policy_id", tip("Policy id", "A short name for this policy. It is recorded with every decision in the audit log, together with the revision.")),
      shiny::textAreaInput("description", "Description", rows = 3),
      shiny::selectInput("default_action", tip("When no rule matches", "What happens to an identifier that no rule matches. block is the safest: anything not explicitly allowed stops the request."), actions),
      shiny::numericInput("min_confidence", tip("Minimum confidence (0-1)", "Matches scored below this are ignored. For example, an order number that passes the Aadhaar checksum by chance scores about 0.42."), 0.5, min = 0, max = 1, step = 0.05),
      section("Save"),
      shiny::textInput("user", tip("Your name", "Recorded in the change log with every save. On Shiny Server it is filled in from the signed-in user.")),
      shiny::textInput("note", tip("Why this change", "A few words for the change log, such as a ticket number or an approval. Reviewers and auditors read it."), placeholder = "e.g. new GPU endpoint approved"),
      shiny::uiOutput("save_anyway_ui"),
      bslib::tooltip(shiny::actionButton("save", "Save new revision", class = "btn-primary"), "Writes the policy with its revision raised by one and adds an entry to the change log. Only possible when the draft is valid and has changes."),
      bslib::tooltip(shiny::actionButton("reload", "Discard changes", class = "btn-link btn-sm"), "Throws away the draft and reloads the saved file.")
      )
    ),
    shiny::uiOutput("stats", class = "cg-stats"),
    bslib::navset_card_tab(
      id = "tabs",
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
            shiny::selectInput("try_endpoint", tip("Sent to", "The endpoint the request would go to. Its tier and name decide which rules apply."), NULL, width = "100%"),
            shiny::div(
              class = "cg-actions cg-field-row",
              shiny::textInput("test_id", tip("Test id", "A short name for the test, such as card-blocked-for-claude."), placeholder = "e.g. card-blocked-for-claude"),
              bslib::tooltip(
                shiny::actionButton("test_add", "Save as a test", class = "btn-outline-primary btn-sm"),
                "Check the decision is right first. Adds this text, endpoint and decision to the tests file beside the policy, so every later change must keep it."
              )
            )
          ),
          shiny::div(
            shiny::uiOutput("try_result"),
            shiny::uiOutput("try_output")
          ),
          col_widths = c(5, 7)
        ),
        shiny::sliderInput(
          "try_min_confidence",
          tip("Minimum confidence", "The same setting as in the sidebar: matches scored below it are ignored. Drag it to see what would be caught or let through; it changes the draft."),
          min = 0, max = 1, value = 0.5, step = 0.05, width = "100%"
        ),
        shiny::uiOutput("try_matches"),
        shiny::uiOutput("try_misses")
      ),
      bslib::nav_panel(
        "Tests",
        shiny::p(class = "cg-lede", shiny::HTML(paste0(
          "Requests and what the policy must do with them, from <code>",
          htmltools::htmlEscape(basename(policy_tests_path(path))),
          "</code> beside the policy. They run against the draft on every change; ",
          "<code>credgate policy test</code> runs them in CI."
        ))),
        shiny::uiOutput("tests_table"),
        shiny::div(
          class = "cg-actions cg-field-row",
          shiny::selectInput("test_pick", "Test", NULL),
          bslib::tooltip(shiny::actionButton("test_delete", "Remove test", class = "btn-outline-danger btn-sm"), "Removes the test from the tests file at once.")
        )
      ),
      bslib::nav_panel(
        "Detectors",
        shiny::p(class = "cg-lede", "Your own detectors (loan account numbers, customer ids, staff codes) in a custom detectors file named in the policy. ",
                 "Edit the file, try it on a sample, and save: the examples are checked first, as on every load. Use synthetic data only."),
        bslib::layout_columns(
          shiny::div(
            shiny::selectInput("det_file", tip("File", "The custom detectors files the policy names, or a new one beside the policy (added to the policy's detectors list)."), NULL, width = "100%"),
            shiny::uiOutput("det_new_name"),
            bslib::accordion(
              open = FALSE,
              bslib::accordion_panel(
                "Add a detector from a form",
                shiny::textInput("gen_id", tip("Id", "Lower-case letters, digits and _, e.g. loan_account. Reported as the type, and used in rules."), placeholder = "loan_account"),
                shiny::selectInput("gen_class", tip("Class", "The group that policy rules can name, e.g. financial. One of the seven classes credgate knows."), custom_classes, selected = "financial"),
                shiny::textInput("gen_label", "Label", placeholder = "Loan account number"),
                shiny::textInput("gen_pattern", tip("Pattern (regex)", "What the value looks like, e.g. LN[0-9]{10} for LN and ten digits. It is not matched inside a longer word or number."), placeholder = "LN[0-9]{10}"),
                shiny::textInput("gen_keywords", tip("Keywords nearby (comma-separated)", "Words that, near a value, make it more certain, e.g. loan, a/c. Taken literally."), placeholder = "loan, a/c"),
                shiny::checkboxInput("gen_required", "Report only with a keyword nearby", FALSE),
                shiny::textAreaInput("gen_match", tip("Should match (one per line)", "Examples that must be found. They are checked every time the file loads."), rows = 2, placeholder = "Loan a/c LN0012345678"),
                shiny::textAreaInput("gen_no_match", tip("Should not match (one per line)", "Examples that must not be found, such as a near-miss you want ignored."), rows = 2, placeholder = "LN00123"),
                bslib::tooltip(
                  shiny::actionButton("gen_add", "Add to the file", class = "btn-outline-primary btn-sm"),
                  "Adds the detector to the YAML below (not saved yet). The file is rewritten in a standard layout, so comments in it are not kept."
                )
              )
            ),
            shiny::textAreaInput("det_yaml", "Detectors (YAML)", rows = 18, width = "100%", resize = "vertical"),
            shiny::div(
              class = "cg-actions",
              bslib::tooltip(shiny::actionButton("det_save", "Save detectors file", class = "btn-primary btn-sm"), "Checks the file as credgate loads it - every example must hold - then writes it and loads it here. Save a new policy revision afterwards so the audit log shows the change."),
              bslib::tooltip(shiny::actionButton("det_revert", "Discard edits", class = "btn-link btn-sm"), "Reloads the file as saved.")
            )
          ),
          shiny::div(
            shiny::uiOutput("det_status"),
            shiny::textAreaInput("det_sample", tip("Sample text", "Text to try the detectors on, one request per line."), rows = 5, width = "100%",
                                 value = "Loan a/c LN0012345678 overdue\nRef LN00123 is not an account"),
            shiny::uiOutput("det_matches"),
            shiny::uiOutput("det_examples")
          ),
          col_widths = bslib::breakpoints(sm = 12, xl = c(5, 7))
        )
      ),
      bslib::nav_panel(
        "My key",
        shiny::p(class = "cg-lede", "Your key for the credgate proxy. Put it where your tool takes an API key (for Claude Code `ANTHROPIC_API_KEY`, for the OpenAI SDK `api_key`) and point the tool at the proxy. It is shown once, when it is made: keep it like a password."),
        shiny::uiOutput("my_key")
      ),
      bslib::nav_panel(
        "Users",
        shiny::p(class = "cg-lede", "Everyone in the users file, their role, and their proxy key. Roles are changed on the server (credgate users ...); keys here."),
        shiny::uiOutput("users_table"),
        shiny::div(
          id = "cg-user-actions", class = "cg-actions cg-field-row",
          shiny::selectInput("user_pick", "User", NULL),
          shiny::selectInput("user_days", tip("Valid for", "How long the new key works. The longest allowed is set on the server (key_max_days)."), NULL),
          bslib::tooltip(shiny::actionButton("user_new_key", "New key", class = "btn-outline-primary btn-sm"), "Makes a key for this user (their old one stops working) and shows it once, for you to hand over."),
          bslib::tooltip(shiny::actionButton("user_remove_key", "Remove key", class = "btn-outline-danger btn-sm"), "Their key stops working at the proxy's next reload.")
        ),
        shiny::h6(class = "cg-section", "Access log"),
        shiny::uiOutput("access_log")
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


policy_editor_server <- function(path, user = NULL, users = NULL, keys = NULL) {
  function(input, output, session) {
    # Who is signed in, and what they may do. Changes to the policy, its tests
    # and detector files are refused here on the server, not only hidden.
    signed_in <- user %||% session$user
    role <- editor_role(users, signed_in)
    if (is.null(role)) {
      shiny::removeUI(".bslib-sidebar-layout")
      shiny::showModal(shiny::modalDialog(
        title = "No access",
        if (is.null(signed_in)) "You are not signed in." else
          sprintf("%s has no access to this app. Ask your InfoSec team.", signed_in),
        footer = NULL, easyClose = FALSE
      ))
      return(invisible())
    }
    can_edit <- identical(role, "admin")
    if (!can_edit) {
      shiny::removeUI("#cg-admin-controls")
      for (control in c("test_add", "test_delete", "det_save", "user_new_key")) {
        shiny::removeUI(sprintf(".cg-actions:has(#%s)", control))
      }
    }
    for (tab in setdiff(editor_tabs$admin, editor_tabs[[role]])) {
      bslib::nav_remove("tabs", tab, session = session)
    }
    output$role_note <- shiny::renderUI({
      if (is.null(users)) {
        return(NULL)
      }
      what <- c(
        admin = "can change the policy",
        auditor = "read-only: sees everything, changes nothing",
        user = "read-only: tries the saved policy"
      )[[role]]
      shiny::div(class = "cg-status neutral", shiny::strong(sprintf("%s \u00b7 %s. ", signed_in, role)), what)
    })

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

    edit <- function(f) if (can_edit) policy(f(policy()))

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
    shiny::observeEvent(policy()$min_confidence %||% 0, {
      v <- policy()$min_confidence %||% 0
      if (!identical(as.numeric(input$try_min_confidence), as.numeric(v))) {
        shiny::updateSliderInput(session, "try_min_confidence", value = v)
      }
    })
    shiny::observeEvent(input$try_min_confidence, {
      if (!identical(as.numeric(input$try_min_confidence), as.numeric(policy()$min_confidence %||% 0))) {
        shiny::updateNumericInput(session, "min_confidence", value = input$try_min_confidence)
      }
    }, ignoreInit = TRUE)
    shiny::observeEvent(input$min_confidence, edit(function(x) {
      if (!(is.null(x$min_confidence) && identical(as.numeric(input$min_confidence), 0))) {
        x$min_confidence <- input$min_confidence
      }
      x
    }), ignoreInit = TRUE)

    det_saved_at <- shiny::reactiveVal(0)
    problem <- shiny::reactive({
      det_saved_at() # a saved detectors file can make the policy valid
      policy_problem(policy(), dirname(path))
    })
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
        if (is.data.frame(test_results())) {
          r <- test_results()
          cg_badge(sprintf("tests %d/%d", sum(r$passed), nrow(r)), if (all(r$passed)) "allow" else "block")
        },
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
        shiny::tags$thead(shiny::tags$tr(lapply(c("Identifier", "Found (masked)", "Confidence", "Why", "Action", "Decided by"), shiny::tags$th))),
        shiny::tags$tbody(lapply(seq_len(nrow(m)), function(i) shiny::tags$tr(
          shiny::tags$td(shiny::strong(m$type[i]), shiny::div(class = "desc", m$class[i])),
          shiny::tags$td(class = "mono", mask_value(m$value[i], m$class[i])),
          shiny::tags$td(confidence_bar(m$confidence[i])),
          shiny::tags$td(class = "desc", why_list(m$reasons[i])),
          shiny::tags$td(cg_badge(m$action[i], m$action[i])),
          shiny::tags$td(if (is.na(m$rule[i]) || !nzchar(m$rule[i]) || m$rule[i] == "default") "default action" else m$rule[i])
        )))
      ))
    })
    # Candidates that were dropped, so a missed identifier can be explained.
    output$try_misses <- shiny::renderUI({
      shiny::req(is.null(problem()), nzchar(input$try_text))
      x <- tryCatch(
        explain_pii(input$try_text, min_confidence = policy()$min_confidence %||% 0,
                    detectors = cg_policy(policy(), dirname(path))$detectors)$misses,
        error = function(e) NULL
      )
      shiny::tagList(
        shiny::h6(class = "cg-section", tip("Not reported", "Text that looked like an identifier but was dropped, and why. A miss here may be right (an order number that fails the Aadhaar checksum) or a sign that the text needs a keyword or the minimum confidence is too high.")),
        if (is.null(x) || nrow(x) == 0) {
          shiny::div(class = "cg-empty", "Nothing that looked like an identifier was dropped.")
        } else {
          shiny::div(class = "cg-scroll", shiny::tags$table(
            class = "cg-table",
            shiny::tags$thead(shiny::tags$tr(lapply(c("Looked like", "Text (masked)", "Why it was not reported"), shiny::tags$th))),
            shiny::tags$tbody(lapply(seq_len(nrow(x)), function(i) shiny::tags$tr(
              shiny::tags$td(shiny::strong(x$type[i])),
              shiny::tags$td(class = "mono", mask_value(x$value[i], x$class[i])),
              shiny::tags$td(x$why[i])
            )))
          ))
        },
        shiny::div(class = "cg-hint", "Names are found after a cue (Mr., S/o, Name:) or in a column named for names; a name on its own is not. ",
                   "A custom detector can add cues: see the custom detectors guide.")
      )
    })

    # --- tests ---------------------------------------------------------------------
    tests_file <- policy_tests_path(path)
    read_tests <- function() {
      if (!file.exists(tests_file)) {
        return(list())
      }
      yaml::yaml.load(paste(read_utf8_lines(tests_file), collapse = "\n"))$tests %||% list()
    }
    tests <- shiny::reactiveVal(tryCatch(read_tests(), error = function(e) list()))
    # A data frame from run_policy_tests(), or the reason the tests cannot run.
    test_results <- shiny::reactive({
      if (length(tests()) == 0) {
        return(NULL)
      }
      if (!is.null(problem())) {
        return("The draft is not valid, so the tests cannot run.")
      }
      tryCatch(
        run_policy_tests(cg_policy(policy(), dirname(path)), list(kind = "credgate-policy-tests", version = 1, tests = tests())),
        error = function(e) conditionMessage(e)
      )
    })
    failing <- shiny::reactive({
      r <- test_results()
      if (is.data.frame(r)) r$id[!r$passed] else character()
    })
    output$tests_table <- shiny::renderUI({
      r <- test_results()
      if (is.null(r)) {
        return(shiny::div(class = "cg-empty", "No tests yet. In Try it, check a decision is right, then save it as a test."))
      }
      if (is.character(r)) {
        return(shiny::div(class = "cg-alert", r))
      }
      shiny::div(class = "cg-scroll", shiny::tags$table(
        class = "cg-table",
        shiny::tags$thead(shiny::tags$tr(lapply(c("Test", "Endpoint", "Result"), shiny::tags$th))),
        shiny::tags$tbody(lapply(seq_len(nrow(r)), function(i) {
          t <- tests()[[i]]
          shiny::tags$tr(
            `data-pick` = r$id[i], `data-target` = "test_pick",
            class = if (identical(r$id[i], input$test_pick)) "selected",
            shiny::tags$td(shiny::strong(r$id[i]), if (!is.na(r$description[i])) shiny::div(class = "desc", r$description[i])),
            shiny::tags$td(t$endpoint),
            shiny::tags$td(
              if (r$passed[i]) cg_badge("pass", "allow") else cg_badge("fail", "block"),
              lapply(r$problems[[i]], function(p) shiny::div(class = "desc", p))
            )
          )
        }))
      ))
    })
    shiny::observe({
      ids <- vapply(tests(), function(t) t$id, "")
      keep <- shiny::isolate(input$test_pick)
      shiny::updateSelectInput(session, "test_pick", choices = ids,
                               selected = if (!is.null(keep) && keep %in% ids) keep else ids[1])
    })
    save_tests <- function(x) {
      if (!can_edit) {
        return(FALSE)
      }
      ok <- tryCatch({
        types <- tryCatch(names(cg_policy(policy(), dirname(path))$detectors), error = function(e) names(get_detectors(NULL)))
        if (length(x)) write_policy_tests(x, tests_file, types) else unlink(tests_file)
        TRUE
      }, error = function(e) {
        shiny::showNotification(paste("Tests not saved:", conditionMessage(e)), type = "error")
        FALSE
      })
      if (ok) tests(x)
      ok
    }
    shiny::observeEvent(input$test_add, {
      id <- trimws(input$test_id %||% "")
      if (!nzchar(id)) {
        shiny::showNotification("Give the test an id.", type = "error")
        return()
      }
      if (id %in% vapply(tests(), function(t) t$id, "")) {
        shiny::showNotification(sprintf("There is already a test %s.", id), type = "error")
        return()
      }
      d <- tryCatch(decision(), error = function(e) NULL)
      if (is.null(d)) {
        shiny::showNotification("Nothing to save: fix the policy and enter a request first.", type = "error")
        return()
      }
      t <- policy_test_from_decision(id, input$try_text, input$try_endpoint, d)
      if (save_tests(c(tests(), list(t)))) {
        shiny::updateTextInput(session, "test_id", value = "")
        shiny::showNotification(sprintf("Test %s saved to %s.", id, basename(tests_file)), type = "message")
      }
    })
    shiny::observeEvent(input$test_delete, {
      keep <- Filter(function(t) !identical(t$id, input$test_pick), tests())
      if (length(keep) < length(tests())) save_tests(keep)
    })
    output$save_anyway_ui <- shiny::renderUI({
      f <- failing()
      if (length(f) == 0) {
        return(NULL)
      }
      shiny::div(
        class = "cg-alert",
        sprintf("%d test%s fail%s: %s.", length(f), if (length(f) == 1) "" else "s",
                if (length(f) == 1) "s" else "", paste(f, collapse = ", ")),
        shiny::checkboxInput("save_anyway", "Save anyway (the change log records the failing tests; give the reason above)",
                             value = shiny::isolate(isTRUE(input$save_anyway)))
      )
    })

    # --- detector workbench --------------------------------------------------------
    det_template <- paste(
      "kind: credgate-detectors",
      "version: 1",
      "detectors:",
      "  - id: loan_account",
      "    class: financial",
      "    label: Loan account number",
      "    patterns: ['LN[0-9]{10}']",
      "    bounded: true",
      "    context: 'loan|\\ba/c\\b'",
      "    base: 0.6",
      "    base_without_context: 0.4",
      "    examples:",
      "      match: ['Loan a/c LN0012345678']",
      "      no_match: ['LN00123']",
      "", sep = "\n"
    )
    det_files <- shiny::reactive(as.character(unlist(policy()$detectors)))
    det_path <- function(f) if (grepl("^(/|~|[A-Za-z]:)", f)) f else file.path(dirname(path), f)
    shiny::observe({
      files <- det_files()
      keep <- shiny::isolate(input$det_file)
      shiny::updateSelectInput(session, "det_file", choices = c(files, "(new file)" = ""),
                               selected = if (!is.null(keep) && keep %in% files) keep else if (length(files)) files[1] else "")
    })
    output$det_new_name <- shiny::renderUI({
      if (nzchar(input$det_file %||% "")) {
        return(NULL)
      }
      shiny::textInput("det_name", tip("New file name", "Saved beside the policy, e.g. bank-detectors.yaml."), placeholder = "bank-detectors.yaml", width = "100%")
    })
    det_load <- function() {
      f <- input$det_file %||% ""
      text <- if (nzchar(f) && file.exists(det_path(f))) paste(read_utf8_lines(det_path(f)), collapse = "\n") else det_template
      shiny::updateTextAreaInput(session, "det_yaml", value = text)
    }
    shiny::observeEvent(input$det_file, det_load(), ignoreNULL = FALSE)
    shiny::observeEvent(input$det_revert, det_load())

    det_text <- shiny::debounce(shiny::reactive(input$det_yaml %||% ""), 400)
    # The file as edited: its detectors (examples set aside), each example's
    # result, or the reason it cannot be read.
    det_check <- shiny::reactive({
      text <- det_text()
      shiny::req(nzchar(text))
      data <- tryCatch(yaml::yaml.load(text), error = function(e) e)
      if (inherits(data, "error")) {
        return(list(error = paste("Not valid YAML:", conditionMessage(data))))
      }
      examples <- if (is.list(data) && is.list(data$detectors)) lapply(data$detectors, function(d) d$examples)
      bare <- data
      if (is.list(bare$detectors)) bare$detectors <- lapply(bare$detectors, function(d) d[setdiff(names(d), "examples")])
      compiled <- tryCatch(compile_detector_file(bare), error = function(e) e)
      if (inherits(compiled, "error")) {
        return(list(error = conditionMessage(compiled)))
      }
      dets <- lapply(compiled, `[[`, "detector")
      builtin <- intersect(vapply(dets, `[[`, "", "id"), the$builtin_ids)
      if (length(builtin)) {
        return(list(error = sprintf("`%s` is the id of a built-in detector; choose another.", builtin[1])))
      }
      results <- do.call(rbind, c(list(data.frame(id = character(), want = character(), text = character(), ok = logical())),
        Map(function(det, ex) {
          rows <- lapply(c("match", "no_match"), function(want) {
            texts <- as.character(unlist(ex[[want]]))
            if (length(texts) == 0) return(NULL)
            hit <- seq_along(texts) %in% detect_with(list(det), texts)$doc
            data.frame(id = det$id, want = want, text = texts, ok = if (want == "match") hit else !hit)
          })
          do.call(rbind, rows)
        }, dets, examples)))
      list(dets = dets, examples = results)
    })
    output$det_status <- shiny::renderUI({
      x <- det_check()
      if (!is.null(x$error)) {
        return(shiny::div(class = "cg-status bad", shiny::strong("Cannot be saved. "), x$error))
      }
      bad <- sum(!x$examples$ok)
      ids <- paste(vapply(x$dets, `[[`, "", "id"), collapse = ", ")
      if (bad) {
        shiny::div(class = "cg-status bad", shiny::strong(sprintf("%d example%s fail%s. ", bad, if (bad == 1) "" else "s", if (bad == 1) "s" else "")),
                   "Fix the pattern or the example before saving.")
      } else {
        shiny::div(class = "cg-status ok", shiny::strong("Valid. "), sprintf("%s; %d example%s hold.", ids, nrow(x$examples), if (nrow(x$examples) == 1) "" else "s"))
      }
    })
    output$det_matches <- shiny::renderUI({
      x <- det_check()
      shiny::req(is.null(x$error))
      lines <- strsplit(input$det_sample %||% "", "\n", fixed = TRUE)[[1]]
      lines <- lines[nzchar(trimws(lines))]
      if (length(lines) == 0) {
        return(NULL)
      }
      misses <- new.env()
      found <- tryCatch(detect_with(x$dets, lines, misses = misses), error = function(e) NULL)
      shiny::req(!is.null(found))
      m <- misses$spans
      shiny::tagList(
        shiny::h6(class = "cg-section", "On the sample"),
        shiny::div(class = "cg-sample", lapply(seq_along(lines), function(i) {
          f <- found[found$doc == i, , drop = FALSE]
          shiny::div(class = "line", highlight_spans(lines[i], f))
        })),
        if (nrow(found)) shiny::div(class = "cg-scroll", shiny::tags$table(
          class = "cg-table",
          shiny::tags$thead(shiny::tags$tr(lapply(c("Detector", "Found", "Confidence", "Why"), shiny::tags$th))),
          shiny::tags$tbody(lapply(seq_len(nrow(found)), function(i) shiny::tags$tr(
            shiny::tags$td(shiny::strong(found$type[i])),
            shiny::tags$td(class = "mono", found$value[i]),
            shiny::tags$td(confidence_bar(found$confidence[i])),
            shiny::tags$td(class = "desc", why_list(found$reasons[i]))
          )))
        )) else shiny::div(class = "cg-empty", "No matches on the sample."),
        if (!is.null(m) && nrow(m)) shiny::div(class = "cg-hint", lapply(seq_len(nrow(m)), function(i) {
          shiny::div(sprintf("Not reported: %s '%s' - %s", m$type[i], m$value[i], m$why[i]))
        }))
      )
    })
    output$det_examples <- shiny::renderUI({
      x <- det_check()
      shiny::req(is.null(x$error), nrow(x$examples) > 0)
      e <- x$examples
      shiny::tagList(
        shiny::h6(class = "cg-section", "Examples"),
        shiny::div(class = "cg-scroll", shiny::tags$table(
          class = "cg-table",
          shiny::tags$thead(shiny::tags$tr(lapply(c("Example", "Should", "Result"), shiny::tags$th))),
          shiny::tags$tbody(lapply(seq_len(nrow(e)), function(i) shiny::tags$tr(
            shiny::tags$td(class = "mono", e$text[i], if (length(unique(e$id)) > 1) shiny::div(class = "desc", e$id[i])),
            shiny::tags$td(if (e$want[i] == "match") "match" else "not match"),
            shiny::tags$td(if (e$ok[i]) cg_badge("holds", "allow") else cg_badge(if (e$want[i] == "match") "missed" else "wrong match", "block"))
          )))
        ))
      )
    })
    shiny::observeEvent(input$gen_add, {
      det <- detector_from_form(
        id = input$gen_id, class = input$gen_class, label = input$gen_label,
        pattern = input$gen_pattern, keywords = input$gen_keywords,
        required = isTRUE(input$gen_required),
        match = input$gen_match, no_match = input$gen_no_match
      )
      if (is.character(det)) {
        shiny::showNotification(det, type = "error")
        return()
      }
      text <- input$det_yaml %||% ""
      data <- if (nzchar(trimws(text))) tryCatch(yaml::yaml.load(text), error = function(e) NULL) else list()
      if (!is.list(data)) {
        shiny::showNotification("The YAML below cannot be read; fix it before adding a detector.", type = "error")
        return()
      }
      if (det$id %in% vapply(data$detectors %||% list(), function(d) d$id %||% "", "")) {
        shiny::showNotification(sprintf("The file already has a detector %s.", det$id), type = "error")
        return()
      }
      data$kind <- "credgate-detectors"
      data$version <- 1L
      data$detectors <- c(data$detectors, list(det))
      data <- data[c("kind", "version", setdiff(names(data), c("kind", "version")))]
      shiny::updateTextAreaInput(session, "det_yaml", value = detectors_yaml(data))
      for (f in c("gen_id", "gen_label", "gen_pattern", "gen_keywords")) shiny::updateTextInput(session, f, value = "")
      for (f in c("gen_match", "gen_no_match")) shiny::updateTextAreaInput(session, f, value = "")
    })
    shiny::observeEvent(input$det_save, {
      if (!can_edit) {
        return()
      }
      f <- input$det_file %||% ""
      new <- !nzchar(f)
      if (new) {
        f <- trimws(input$det_name %||% "")
        if (!grepl("^[A-Za-z0-9][A-Za-z0-9._-]*\\.ya?ml$", f)) {
          shiny::showNotification("Give the new file a name ending in .yaml, without folders, e.g. bank-detectors.yaml.", type = "error")
          return()
        }
        if (file.exists(det_path(f))) {
          shiny::showNotification(sprintf("%s already exists; add it to the policy's detectors list to edit it.", f), type = "error")
          return()
        }
      }
      text <- input$det_yaml %||% ""
      data <- tryCatch(yaml::yaml.load(text), error = function(e) e)
      ok <- !inherits(data, "error") && tryCatch({
        ids <- vapply(compile_detector_file(data), function(c) c$detector$id, "")
        builtin <- intersect(ids, the$builtin_ids)
        if (length(builtin)) stop(sprintf("`%s` is the id of a built-in detector.", builtin[1]), call. = FALSE)
        TRUE
      }, error = function(e) {
        shiny::showNotification(paste("Not saved:", conditionMessage(e)), type = "error")
        FALSE
      })
      if (!ok) {
        if (inherits(data, "error")) shiny::showNotification("Not saved: not valid YAML.", type = "error")
        return()
      }
      target <- det_path(f)
      tmp <- paste0(target, ".tmp")
      writeLines(enc2utf8(sub("\n*$", "\n", text)), tmp, useBytes = TRUE, sep = "")
      file.rename(tmp, target)
      if (new) {
        edit(function(x) {
          x$detectors <- c(x$detectors, list(f))
          x
        })
        shiny::updateSelectInput(session, "det_file", selected = f)
      }
      det_saved_at(det_saved_at() + 1)
      shiny::showNotification(sprintf(
        "Saved %s. Save a new policy revision too, so the audit log shows the change.", basename(target)
      ), type = "message", duration = 8)
    })

    # --- proxy keys ----------------------------------------------------------------
    me <- signed_in %||% who
    keys_changed <- shiny::reactiveVal(0)
    users_file <- shiny::reactive({
      keys_changed()
      if (is.null(users)) NULL else tryCatch(cg_users(users), error = function(e) NULL)
    })
    durations <- shiny::reactive({
      max_days <- users_file()$settings$key_max_days %||% 90L
      key_durations[key_durations <= max_days]
    })
    show_new_key <- function(title, key, for_whom) {
      shiny::showModal(shiny::modalDialog(
        title = title, easyClose = FALSE,
        shiny::p(sprintf("The key for %s. Copy it now: it is not shown again, and credgate keeps only a hash of it.", for_whom)),
        shiny::tags$pre(class = "cg-out", id = "cg-new-key", key),
        footer = shiny::tagList(
          shiny::tags$button(type = "button", class = "btn btn-outline-primary",
                             onclick = "navigator.clipboard.writeText(document.getElementById('cg-new-key').innerText)", "Copy"),
          shiny::modalButton("Done")
        )
      ))
    }
    key_row <- function(name) {
      u <- proxy_users(keys)
      u[u$name == name, , drop = FALSE]
    }
    output$my_key <- shiny::renderUI({
      keys_changed()
      if (is.null(keys)) {
        return(shiny::div(class = "cg-empty", "No keys file is set up for this app; ask your InfoSec team."))
      }
      row <- tryCatch(key_row(me), error = function(e) NULL)
      has_key <- !is.null(row) && nrow(row) == 1
      shiny::tagList(
        if (has_key) {
          shiny::div(class = "cg-status neutral",
                     shiny::strong(sprintf("%s: %s. ", me, row$status)),
                     sprintf("Made %s, valid until %s.", substr(row$created %|% "-", 1, 10), substr(row$expires %|% "never", 1, 10)))
        } else {
          shiny::div(class = "cg-empty", sprintf("%s has no proxy key yet.", me))
        },
        shiny::div(
          class = "cg-actions cg-field-row",
          shiny::selectInput("my_days", "Valid for", durations(), selected = max(durations())),
          shiny::actionButton("my_new_key", if (has_key) "New key (the old one stops working)" else "Make my key", class = "btn-primary btn-sm"),
          if (has_key) shiny::actionButton("my_remove_key", "Delete my key", class = "btn-outline-danger btn-sm")
        )
      )
    })
    days_ok <- function(days) {
      days <- suppressWarnings(as.integer(days))
      if (is.na(days) || !days %in% durations()) {
        shiny::showNotification("Choose how long the key is valid.", type = "error")
        return(NULL)
      }
      days
    }
    make_key <- function(name, days, by) {
      exists <- file.exists(keys) && name %in% proxy_users(keys)$name
      key <- if (exists) proxy_rotate_key(keys, name, days) else proxy_add_user(keys, name, days)
      log_access(keys, by, if (exists) "rotate" else "create", name, key_row(name)$expires)
      keys_changed(keys_changed() + 1)
      key
    }
    shiny::observeEvent(input$my_new_key, {
      days <- days_ok(input$my_days)
      if (is.null(days) || is.null(keys)) {
        return()
      }
      key <- tryCatch(make_key(me, days, me), error = function(e) {
        shiny::showNotification(conditionMessage(e), type = "error")
        NULL
      })
      if (!is.null(key)) show_new_key("Your new key", key, me)
    })
    shiny::observeEvent(input$my_remove_key, {
      if (is.null(keys)) {
        return()
      }
      ok <- tryCatch({
        proxy_remove_user(keys, me)
        log_access(keys, me, "remove", me)
        TRUE
      }, error = function(e) {
        shiny::showNotification(conditionMessage(e), type = "error")
        FALSE
      })
      if (ok) {
        keys_changed(keys_changed() + 1)
        shiny::showNotification("Your key is deleted; it stops working at the proxy's next reload.", type = "message")
      }
    })
    output$users_table <- shiny::renderUI({
      keys_changed()
      u <- users_file()
      k <- if (!is.null(keys) && file.exists(keys)) proxy_users(keys) else proxy_users(tempfile())
      people <- if (!is.null(u)) u$users else data.frame(name = k$name, role = NA_character_, active = TRUE)
      if (nrow(people) == 0) {
        return(shiny::div(class = "cg-empty", "No users yet."))
      }
      shiny::div(class = "cg-scroll", shiny::tags$table(
        class = "cg-table",
        shiny::tags$thead(shiny::tags$tr(lapply(c("User", "Role", "Access", "Proxy key", "Valid until"), shiny::tags$th))),
        shiny::tags$tbody(lapply(seq_len(nrow(people)), function(i) {
          kr <- k[k$name == people$name[i], , drop = FALSE]
          shiny::tags$tr(
            shiny::tags$td(shiny::strong(people$name[i])),
            shiny::tags$td(people$role[i] %|% "-"),
            shiny::tags$td(if (people$active[i]) cg_badge("active", "allow") else cg_badge("inactive", "block")),
            shiny::tags$td(if (nrow(kr)) kr$status else "none"),
            shiny::tags$td(class = "mono", if (nrow(kr)) substr(kr$expires %|% "-", 1, 10) else "-")
          )
        }))
      ))
    })
    shiny::observe({
      u <- users_file()
      names <- if (!is.null(u)) u$users$name else if (!is.null(keys) && file.exists(keys)) proxy_users(keys)$name else character()
      shiny::updateSelectInput(session, "user_pick", choices = names, selected = shiny::isolate(input$user_pick))
      shiny::updateSelectInput(session, "user_days", choices = durations(), selected = max(durations()))
    })
    shiny::observeEvent(input$user_new_key, {
      if (!can_edit || is.null(keys) || !nzchar(input$user_pick %||% "")) {
        return()
      }
      days <- days_ok(input$user_days)
      if (is.null(days)) {
        return()
      }
      key <- tryCatch(make_key(input$user_pick, days, me), error = function(e) {
        shiny::showNotification(conditionMessage(e), type = "error")
        NULL
      })
      if (!is.null(key)) show_new_key(sprintf("New key for %s", input$user_pick), key, input$user_pick)
    })
    shiny::observeEvent(input$user_remove_key, {
      if (!can_edit || is.null(keys) || !nzchar(input$user_pick %||% "")) {
        return()
      }
      tryCatch({
        proxy_remove_user(keys, input$user_pick)
        log_access(keys, me, "remove", input$user_pick)
        keys_changed(keys_changed() + 1)
        shiny::showNotification(sprintf("%s's key is removed.", input$user_pick), type = "message")
      }, error = function(e) shiny::showNotification(conditionMessage(e), type = "error"))
    })
    output$access_log <- shiny::renderUI({
      keys_changed()
      if (is.null(keys)) {
        return(NULL)
      }
      a <- proxy_access(keys)
      alert <- if (!isTRUE(attr(a, "intact"))) shiny::div(class = "cg-alert", "The access log was altered: entries were edited or removed after they were written.")
      if (nrow(a) == 0) {
        return(shiny::tagList(alert, shiny::div(class = "cg-empty", "No key changes yet.")))
      }
      a <- a[rev(seq_len(nrow(a))), ]
      shiny::tagList(alert, shiny::tags$ul(class = "cg-diff", lapply(seq_len(nrow(a)), function(i) shiny::tags$li(sprintf(
        "%s · %s: %s key for %s%s", sub("T", " ", sub("Z$", "", a$time[i])), a$by[i], a$action[i], a$user[i],
        if (is.na(a$expires[i])) "" else paste0(", valid until ", substr(a$expires[i], 1, 10))
      )))))
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
      if (identical(role, "user")) {
        # Users see when the policy changed, not who changed it or why.
        if (nrow(h) == 0) {
          return(shiny::div(class = "cg-empty", "The policy has not been changed yet."))
        }
        h <- h[rev(seq_len(nrow(h))), ]
        return(shiny::tags$ul(class = "cg-diff", lapply(seq_len(nrow(h)), function(i) shiny::tags$li(sprintf(
          "Revision %d \u00b7 %s \u00b7 %d change%s", h$revision[i], substr(h$time[i], 1, 10),
          length(h$changes[[i]]), if (length(h$changes[[i]]) == 1) "" else "s"
        )))))
      }
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
    can_save <- shiny::reactive({
      is.null(problem()) && length(changes()) > 0 &&
        (length(failing()) == 0 || isTRUE(input$save_anyway))
    })
    shiny::observe({
      shiny::updateActionButton(session, "save", disabled = !can_save())
    })
    shiny::observeEvent(input$save, {
      if (!can_edit) {
        return()
      }
      if (!can_save()) {
        return()
      }
      if (!nzchar(trimws(input$user))) {
        shiny::showNotification("Enter your name for the change log.", type = "error")
        return()
      }
      note <- trimws(input$note)
      if (length(failing())) {
        if (!nzchar(note)) {
          shiny::showNotification("Tests fail: say why you are saving anyway under \"Why this change\".", type = "error")
          return()
        }
        note <- sprintf("%s [saved with failing tests: %s]", note, paste(failing(), collapse = ", "))
      }
      x <- policy()
      x$revision <- saved()$revision
      written <- tryCatch(
        policy_write(x, path, user = trimws(input$user), note = note),
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
        shiny::updateCheckboxInput(session, "save_anyway", value = FALSE)
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

# A confidence score as a small bar with its value.
confidence_bar <- function(x) {
  shiny::span(class = "cg-conf", shiny::span(class = "bar", shiny::span(style = sprintf("width:%d%%", round(100 * x)))),
              sprintf("%.2f", x))
}

# A custom detector definition from the workbench form, or a message saying
# what is missing.
detector_from_form <- function(id, class, label, pattern, keywords, required, match, no_match) {
  id <- trimws(id %||% "")
  pattern <- trimws(pattern %||% "")
  if (!grepl("^[a-z][a-z0-9_]*$", id)) {
    return("Give an id in lower-case letters, digits and _, starting with a letter, e.g. loan_account.")
  }
  if (!nzchar(pattern)) {
    return("Give a pattern, e.g. LN[0-9]{10}.")
  }
  if (inherits(tryCatch(stringi::stri_detect_regex("", pattern), error = function(e) e), "error")) {
    return("The pattern is not a valid regular expression.")
  }
  words <- trimws(strsplit(keywords %||% "", ",", fixed = TRUE)[[1]])
  words <- words[nzchar(words)]
  if (required && length(words) == 0) {
    return("Give at least one keyword, or untick \"only with a keyword nearby\".")
  }
  lines <- function(x) {
    x <- trimws(strsplit(x %||% "", "\n", fixed = TRUE)[[1]])
    as.list(x[nzchar(x)])
  }
  det <- list(id = id, class = class, label = if (nzchar(trimws(label %||% ""))) trimws(label) else id,
              patterns = list(pattern), bounded = TRUE)
  if (length(words)) {
    det$context <- paste(stringi::stri_replace_all_regex(words, "([\\\\^$.|?*+()\\[\\]{}])", "\\\\$1"), collapse = "|")
    if (required) {
      det$context_required <- TRUE
      det$base <- 0.5
    } else {
      det$base <- 0.6
      det$base_without_context <- 0.4
    }
  } else {
    det$base <- 0.6
  }
  examples <- list(match = lines(match), no_match = lines(no_match))
  examples <- examples[lengths(examples) > 0]
  if (length(examples)) det$examples <- examples
  det
}

# A custom detectors file as YAML; logicals as true/false.
detectors_yaml <- function(data) {
  # yaml.load() reads a one-item list as a single value; write it as a list.
  seq <- function(x) if (is.null(x)) NULL else as.list(unlist(x))
  data$lists <- if (!is.null(data$lists)) lapply(data$lists, seq)
  data$detectors <- lapply(data$detectors, function(d) {
    d$patterns <- seq(d$patterns)
    if (!is.null(d$column_label)) d$column_label$patterns <- seq(d$column_label$patterns)
    for (k in c("match", "no_match")) if (!is.null(d$examples[[k]])) d$examples[[k]] <- seq(d$examples[[k]])
    d
  })
  yaml::as.yaml(data, indent.mapping.sequence = TRUE, handlers = list(
    logical = function(x) structure(ifelse(x, "true", "false"), class = "verbatim")
  ))
}

# A line of text with the given spans (from detection) highlighted.
highlight_spans <- function(line, spans) {
  spans <- spans[order(spans$start), , drop = FALSE]
  out <- list()
  at <- 1L
  for (i in seq_len(nrow(spans))) {
    if (spans$start[i] < at) next
    if (spans$start[i] > at) out[[length(out) + 1]] <- stringi::stri_sub(line, at, spans$start[i] - 1L)
    out[[length(out) + 1]] <- shiny::tags$mark(title = spans$type[i], stringi::stri_sub(line, spans$start[i], spans$end[i]))
    at <- spans$end[i] + 1L
  }
  if (at <= nchar(line)) out[[length(out) + 1]] <- stringi::stri_sub(line, at)
  out
}

# A detection's reasons ("matched PAN pattern; context 'PAN'") as lines.
why_list <- function(reasons) {
  lapply(strsplit(reasons, "; ", fixed = TRUE)[[1]], shiny::div)
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
