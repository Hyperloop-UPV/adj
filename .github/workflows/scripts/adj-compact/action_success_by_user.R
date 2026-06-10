#!/usr/bin/env Rscript

# action_success_by_user.R
# ---------------------------------------------------------------------------
# Fetch GitHub Actions workflow-run usage and plot the relative percentage of
# successful runs, grouped by the user who triggered each run.
#
# Usage:
#   Rscript action_success_by_user.R owner/repo
#   Rscript action_success_by_user.R --org my-org
#   Rscript action_success_by_user.R owner/repo --out chart.png --max 1000
#
# Auth:
#   Set a token in the environment to avoid the 60 req/hour unauthenticated
#   limit (and to read private repos):
#       export GITHUB_TOKEN=ghp_xxx
# ---------------------------------------------------------------------------

suppressWarnings(suppressMessages({
  ok <- requireNamespace("httr", quietly = TRUE) &&
        requireNamespace("jsonlite", quietly = TRUE)
}))
if (!ok) {
  stop("This script needs the 'httr' and 'jsonlite' packages.\n",
       "Install them with: install.packages(c('httr','jsonlite'))",
       call. = FALSE)
}

# ---- argument parsing ------------------------------------------------------

DEFAULT_REPO <- "Hyperloop-UPV/adj"

parse_args <- function(args) {
  out <- list(repo = NULL, org = NULL, out = "action_success_by_user.png",
              max = Inf, logo = NULL)
  i <- 1
  while (i <= length(args)) {
    a <- args[[i]]
    if (a == "--org") {
      out$org <- args[[i + 1]]; i <- i + 2
    } else if (a == "--out") {
      out$out <- args[[i + 1]]; i <- i + 2
    } else if (a == "--max") {
      out$max <- as.numeric(args[[i + 1]]); i <- i + 2
    } else if (a == "--logo") {
      out$logo <- args[[i + 1]]; i <- i + 2
    } else if (!startsWith(a, "--")) {
      out$repo <- a; i <- i + 1
    } else {
      stop("Unknown argument: ", a, call. = FALSE)
    }
  }
  out
}

opts <- parse_args(commandArgs(trailingOnly = TRUE))

if (is.null(opts$repo) && is.null(opts$org)) {
  opts$repo <- DEFAULT_REPO
  message("No repo argument given - using default: ", DEFAULT_REPO)
}

# Auto-detect a logo.png next to the script if none was passed.
if (is.null(opts$logo) && file.exists("logo.png")) opts$logo <- "logo.png"

token <- Sys.getenv("GITHUB_TOKEN", Sys.getenv("GH_TOKEN", ""))
gh_headers <- httr::add_headers(
  Accept = "application/vnd.github+json",
  `X-GitHub-Api-Version` = "2022-11-28",
  Authorization = if (nzchar(token)) paste("Bearer", token) else NULL
)
if (!nzchar(token)) {
  message("No GITHUB_TOKEN found - using unauthenticated API (60 req/hour limit).")
}

# ---- generic paginated GET -------------------------------------------------

gh_get_all <- function(url, query = list(), item_key = NULL, max_items = Inf) {
  per_page <- 100
  page <- 1
  items <- list()
  repeat {
    q <- modifyList(query, list(per_page = per_page, page = page))
    resp <- httr::GET(url, gh_headers, query = q)
    if (httr::status_code(resp) == 403 &&
        identical(httr::headers(resp)[["x-ratelimit-remaining"]], "0")) {
      stop("GitHub API rate limit exceeded. Set GITHUB_TOKEN to raise it.",
           call. = FALSE)
    }
    httr::stop_for_status(resp, task = paste("fetch", url))
    body <- httr::content(resp, as = "text", encoding = "UTF-8")
    parsed <- jsonlite::fromJSON(body, simplifyVector = FALSE)
    batch <- if (is.null(item_key)) parsed else parsed[[item_key]]
    if (length(batch) == 0) break
    items <- c(items, batch)
    if (length(items) >= max_items) {
      items <- items[seq_len(min(length(items), max_items))]
      break
    }
    if (length(batch) < per_page) break
    page <- page + 1
  }
  items
}

# ---- collect workflow runs -------------------------------------------------

list_org_repos <- function(org) {
  message("Listing repositories for org/user: ", org)
  # Try org endpoint first, fall back to user endpoint.
  url <- sprintf("https://api.github.com/orgs/%s/repos", org)
  resp <- httr::GET(url, gh_headers, query = list(per_page = 1))
  if (httr::status_code(resp) == 404) {
    url <- sprintf("https://api.github.com/users/%s/repos", org)
  }
  repos <- gh_get_all(url)
  vapply(repos, function(r) r$full_name, character(1))
}

fetch_runs_for_repo <- function(full_name, max_items = Inf) {
  message("Fetching workflow runs for ", full_name, " ...")
  url <- sprintf("https://api.github.com/repos/%s/actions/runs", full_name)
  gh_get_all(url, item_key = "workflow_runs", max_items = max_items)
}

repos <- if (!is.null(opts$org)) list_org_repos(opts$org) else opts$repo

runs <- list()
for (r in repos) {
  remaining <- opts$max - length(runs)
  if (remaining <= 0) break
  runs <- c(runs, fetch_runs_for_repo(r, max_items = remaining))
}

if (length(runs) == 0) {
  stop("No workflow runs found.", call. = FALSE)
}
message("Collected ", length(runs), " workflow runs.")

# ---- reduce to a tidy data frame ------------------------------------------

safe <- function(x, default = NA_character_) if (is.null(x)) default else x

df <- do.call(rbind, lapply(runs, function(run) {
  data.frame(
    user       = safe(run$actor$login, "(unknown)"),
    status     = safe(run$status),
    conclusion = safe(run$conclusion, "(none)"),
    stringsAsFactors = FALSE
  )
}))

# Users to exclude from the analysis (e.g. bots).
EXCLUDE_USERS <- c("Copilot")
df <- df[!df$user %in% EXCLUDE_USERS, , drop = FALSE]

# Only count runs that have actually finished (have a conclusion).
df <- df[df$status == "completed" & !is.na(df$conclusion), , drop = FALSE]
if (nrow(df) == 0) {
  stop("No completed runs with a conclusion to summarise.", call. = FALSE)
}

# ---- per-user success percentage ------------------------------------------

agg <- aggregate(
  list(total = rep(1, nrow(df)),
       success = as.integer(df$conclusion == "success")),
  by = list(user = df$user),
  FUN = sum
)
agg$pct_success <- round(100 * agg$success / agg$total, 1)
# Order from lowest to highest success rate.
agg <- agg[order(agg$pct_success, agg$total), ]

message("\nSuccess rate by user:")
print(agg, row.names = FALSE)

# ---- plot ------------------------------------------------------------------

title <- "Hyperloop-UPV"
stamp <- format(Sys.time(), "Generado: %Y-%m-%d %H:%M:%S")

if (requireNamespace("ggplot2", quietly = TRUE)) {
  library(ggplot2)
  # Keep the low-to-high ordering on the x axis (vertical bars).
  agg$user <- factor(agg$user, levels = agg$user)
  p <- ggplot(agg, aes(x = user, y = pct_success)) +
    geom_col(fill = "#20274c") +
    geom_text(aes(label = sprintf("%.0f%%\n(%d/%d)", pct_success, success, total)),
              vjust = -0.3, size = 3, lineheight = 0.9) +
    scale_y_continuous(limits = c(0, 100), breaks = seq(0, 100, 20),
                       expand = c(0, 0)) +
    scale_x_discrete(expand = expansion(add = 0.7)) +
    coord_cartesian(ylim = c(0, 100), clip = "off") +
    labs(title = title,
         subtitle = "Percentage of completed workflow runs that succeeded (by user)",
         caption = stamp,
         x = NULL, y = "Success rate (%)") +
    theme_minimal(base_size = 12) +
    theme(axis.text.x = element_text(angle = 45, hjust = 1),
          panel.border = element_rect(color = "black", fill = NA, linewidth = 0.8),
          plot.margin = margin(t = 20, r = 10, b = 5, l = 5))

  w <- max(7, 0.7 * nrow(agg) + 2); h <- 6
  png(opts$out, width = w, height = h, units = "in", res = 120)
  print(p)
  # Overlay the team logo in the top-right corner, preserving its aspect ratio.
  if (!is.null(opts$logo) && file.exists(opts$logo) &&
      requireNamespace("png", quietly = TRUE)) {
    logo <- png::readPNG(opts$logo)
    grid::grid.raster(logo, x = 0.985, y = 0.97, width = grid::unit(0.05, "npc"),
                      just = c("right", "top"))
  } else if (!is.null(opts$logo)) {
    message("Logo not drawn (file or 'png' package missing): ", opts$logo)
  }
  dev.off()
} else {
  message("ggplot2 not installed - using base R barplot.")
  png(opts$out, width = max(700, 70 * nrow(agg) + 120), height = 600)
  par(mar = c(9, 5, 4, 2))
  bp <- barplot(agg$pct_success, names.arg = agg$user, horiz = FALSE,
                las = 2, col = "#20274c", border = NA, ylim = c(0, 100),
                ylab = "Success rate (%)", main = title)
  box()  # black frame around the plot
  text(bp, agg$pct_success + 4,
       labels = sprintf("%.0f%% (%d/%d)", agg$pct_success, agg$success, agg$total),
       cex = 0.8, xpd = TRUE)
  mtext(stamp, side = 1, line = 7, adj = 1, cex = 0.7, col = "gray30")
  dev.off()
}

message("\nSaved chart to: ", normalizePath(opts$out))
