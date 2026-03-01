//! Omnia Lint CLI - Command-line interface for the Omnia linter.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use colored::Colorize;
use omnia_lint::output::{DiagnosticSummary, OutputFormat, format_diagnostics, format_json_all};
use omnia_lint::{LintConfig, Linter, RuleCategory, RuleSeverity, config};
use rayon::prelude::*;
use walkdir::WalkDir;

/// Omnia Lint - A custom Rust linter for WASM32 handler development
#[derive(Parser, Debug)]
#[command(name = "omnia-lint")]
#[command(author = "Augentic Team")]
#[command(version = "0.1.0")]
#[command(about = "Lint Rust code for Omnia WASM32 handler compliance", long_about = None)]
struct Args {
    /// Files or directories to lint
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "pretty")]
    format: OutputFormatArg,

    /// Minimum severity to report
    #[arg(short, long, value_enum, default_value = "hint")]
    severity: SeverityArg,

    /// Rule categories to check (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    categories: Option<Vec<CategoryArg>>,

    /// Rules to disable (comma-separated rule IDs)
    #[arg(long, value_delimiter = ',')]
    disable: Option<Vec<String>>,

    /// Show fix suggestions
    #[arg(long, default_value = "true")]
    show_fixes: bool,

    /// Exit with error code on warnings
    #[arg(long)]
    error_on_warnings: bool,

    /// Only show files with diagnostics
    #[arg(short, long)]
    quiet: bool,

    /// Show rule statistics
    #[arg(long)]
    stats: bool,

    /// Maximum number of diagnostics to show (0 for unlimited)
    #[arg(long, default_value = "0")]
    max_diagnostics: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormatArg {
    /// Human-readable colored output
    Pretty,
    /// JSON output for tooling integration
    Json,
    /// Compact one-line-per-diagnostic
    Compact,
    /// GitHub Actions format
    Github,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum SeverityArg {
    Error,
    Warning,
    Info,
    Hint,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CategoryArg {
    Handler,
    Provider,
    Context,
    Error,
    Response,
    Wasm,
    Stateless,
    Performance,
    Security,
    StrongTyping,
    Caching,
    Time,
    Auth,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Pretty => OutputFormat::Pretty,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Compact => OutputFormat::Compact,
            OutputFormatArg::Github => OutputFormat::Github,
        }
    }
}

impl From<SeverityArg> for RuleSeverity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Error => RuleSeverity::Error,
            SeverityArg::Warning => RuleSeverity::Warning,
            SeverityArg::Info => RuleSeverity::Info,
            SeverityArg::Hint => RuleSeverity::Hint,
        }
    }
}

impl From<CategoryArg> for RuleCategory {
    fn from(arg: CategoryArg) -> Self {
        match arg {
            CategoryArg::Handler => RuleCategory::Handler,
            CategoryArg::Provider => RuleCategory::Provider,
            CategoryArg::Context => RuleCategory::Context,
            CategoryArg::Error => RuleCategory::Error,
            CategoryArg::Response => RuleCategory::Response,
            CategoryArg::Wasm => RuleCategory::Wasm,
            CategoryArg::Stateless => RuleCategory::Stateless,
            CategoryArg::Performance => RuleCategory::Performance,
            CategoryArg::Security => RuleCategory::Security,
            CategoryArg::StrongTyping => RuleCategory::StrongTyping,
            CategoryArg::Caching => RuleCategory::Caching,
            CategoryArg::Time => RuleCategory::Time,
            CategoryArg::Auth => RuleCategory::Auth,
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Discover Cargo.toml configuration from the first path argument
    let cargo_overrides = args
        .paths
        .first()
        .and_then(|p| {
            let start = if p.is_file() { p.parent().unwrap_or(p).to_path_buf() } else { p.clone() };
            match config::discover_config(&start) {
                Ok(cfg) => {
                    if !cfg.is_empty() {
                        if let Some(ref src) = cfg.source {
                            eprintln!(
                                "{} Loaded omnia lint config from {}",
                                "note:".blue().bold(),
                                src.display()
                            );
                        }
                        Some(cfg)
                    } else {
                        None
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} Failed to load Cargo.toml config: {}",
                        "warning:".yellow().bold(),
                        e
                    );
                    None
                }
            }
        })
        .unwrap_or_default();

    // Build configuration
    let config = LintConfig {
        all_rules: args.categories.is_none(),
        categories: args
            .categories
            .map(|cats| cats.into_iter().map(Into::into).collect())
            .unwrap_or_default(),
        disabled_rules: args.disable.unwrap_or_default(),
        min_severity: args.severity.into(),
        show_fixes: args.show_fixes,
        cargo_overrides,
    };

    let linter = Linter::new(config);

    // Collect all Rust files
    let files: Vec<PathBuf> = args
        .paths
        .iter()
        .flat_map(|path| {
            if path.is_dir() {
                WalkDir::new(path)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
                    .map(|e| e.path().to_path_buf())
                    .collect::<Vec<_>>()
            } else {
                vec![path.clone()]
            }
        })
        .collect();

    if files.is_empty() {
        eprintln!("{}", "No Rust files found to lint.".yellow());
        return ExitCode::SUCCESS;
    }

    // Lint files in parallel
    let results: Vec<_> = files
        .par_iter()
        .filter_map(|file| match linter.lint_file(file) {
            Ok(diagnostics) => Some((file.clone(), diagnostics)),
            Err(e) => {
                eprintln!("{}: {} - {}", "Error".red().bold(), file.display(), e);
                None
            }
        })
        .collect();

    // Flatten all diagnostics for summary, truncation, and JSON output
    let all_diagnostics: Vec<(&PathBuf, &omnia_lint::Diagnostic)> = results
        .iter()
        .flat_map(|(file, diags)| diags.iter().map(move |d| (file, d)))
        .collect();

    let summary = DiagnosticSummary::from_diagnostics(
        &all_diagnostics.iter().map(|(_, d)| (*d).clone()).collect::<Vec<_>>(),
    );

    // Collect per-rule counts for --stats
    let mut rule_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (_, diag) in &all_diagnostics {
        *rule_counts.entry(diag.rule_id.clone()).or_insert(0) += 1;
    }

    // Apply max diagnostics limit (consistently across all formats)
    let truncated = args.max_diagnostics > 0 && all_diagnostics.len() > args.max_diagnostics;
    let display_count = if args.max_diagnostics > 0 {
        all_diagnostics.len().min(args.max_diagnostics)
    } else {
        all_diagnostics.len()
    };

    if truncated {
        eprintln!(
            "{} Showing first {} of {} diagnostics",
            "Note:".blue().bold(),
            args.max_diagnostics,
            summary.total
        );
    }

    // Output diagnostics
    let output_format: OutputFormat = args.format.into();

    if matches!(output_format, OutputFormat::Json) {
        let limited: Vec<_> = all_diagnostics
            .iter()
            .take(display_count)
            .map(|(f, d)| (f.as_path(), *d))
            .collect();
        println!("{}", format_json_all(&limited));
    } else {
        let mut shown = 0;
        for (file, diagnostics) in &results {
            if diagnostics.is_empty() && args.quiet {
                continue;
            }
            if diagnostics.is_empty() && !args.quiet {
                let output = format_diagnostics(file, &[], output_format, args.show_fixes);
                print!("{output}");
                continue;
            }

            let remaining = display_count.saturating_sub(shown);
            if remaining == 0 {
                break;
            }
            let to_show = diagnostics.len().min(remaining);
            let output =
                format_diagnostics(file, &diagnostics[..to_show], output_format, args.show_fixes);
            print!("{output}");
            shown += to_show;
        }
    }

    // Print summary
    if summary.total > 0 {
        println!();
        println!("{} {}", "Found".bold(), summary.format_pretty());
    } else {
        println!("{}", "✓ No issues found!".green().bold());
    }

    // Print statistics if requested
    if args.stats && !rule_counts.is_empty() {
        println!();
        println!("{}", "Rule Statistics:".bold().underline());
        let mut sorted_rules: Vec<_> = rule_counts.into_iter().collect();
        sorted_rules.sort_by(|a, b| b.1.cmp(&a.1));
        for (rule_id, count) in sorted_rules.iter().take(10) {
            println!("  {:40} {}", rule_id, count);
        }
    }

    // Determine exit code
    if summary.errors > 0 || (args.error_on_warnings && summary.warnings > 0) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
