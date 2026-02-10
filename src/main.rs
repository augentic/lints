//! QWASR Lint CLI - Command-line interface for the QWASR linter.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use colored::Colorize;
use rayon::prelude::*;
use walkdir::WalkDir;

use qwasr_lint::output::{format_diagnostics, OutputFormat};
use qwasr_lint::{LintConfig, Linter, RuleCategory, RuleSeverity};

/// QWASR Lint - A custom Rust linter for WASM32 handler development
#[derive(Parser, Debug)]
#[command(name = "qwasr-lint")]
#[command(author = "Augentic Team")]
#[command(version = "0.1.0")]
#[command(about = "Lint Rust code for QWASR WASM32 handler compliance", long_about = None)]
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
                    .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
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

    // Aggregate statistics
    let mut total_errors = 0;
    let mut total_warnings = 0;
    let mut total_info = 0;
    let mut total_hints = 0;
    let mut rule_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    let mut all_diagnostics = Vec::new();

    for (file, diagnostics) in &results {
        for diag in diagnostics {
            match diag.severity {
                RuleSeverity::Error => total_errors += 1,
                RuleSeverity::Warning => total_warnings += 1,
                RuleSeverity::Info => total_info += 1,
                RuleSeverity::Hint => total_hints += 1,
            }
            *rule_counts.entry(diag.rule_id.clone()).or_insert(0) += 1;
            all_diagnostics.push((file.clone(), diag.clone()));
        }
    }

    // Apply max diagnostics limit
    if args.max_diagnostics > 0 && all_diagnostics.len() > args.max_diagnostics {
        all_diagnostics.truncate(args.max_diagnostics);
        eprintln!(
            "{} Showing first {} of {} diagnostics",
            "Note:".blue().bold(),
            args.max_diagnostics,
            total_errors + total_warnings + total_info + total_hints
        );
    }

    // Output diagnostics
    let output_format: OutputFormat = args.format.into();

    if matches!(output_format, OutputFormat::Json) {
        // For JSON, output all diagnostics as a single JSON array
        let json_diagnostics: Vec<_> = all_diagnostics
            .iter()
            .map(|(file, diag)| {
                serde_json::json!({
                    "file": file.display().to_string(),
                    "line": diag.line,
                    "column": diag.column,
                    "end_column": diag.end_column,
                    "severity": format!("{:?}", diag.severity).to_lowercase(),
                    "rule_id": diag.rule_id,
                    "rule_name": diag.rule_name,
                    "category": format!("{:?}", diag.category),
                    "message": diag.message,
                    "fix": diag.fix_template,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json_diagnostics).unwrap()
        );
    } else {
        // For other formats, group by file
        for (file, diagnostics) in &results {
            if diagnostics.is_empty() && args.quiet {
                continue;
            }

            if !diagnostics.is_empty() || !args.quiet {
                let output = format_diagnostics(file, diagnostics, output_format, args.show_fixes);
                print!("{}", output);
            }
        }
    }

    // Print summary
    let total = total_errors + total_warnings + total_info + total_hints;

    if total > 0 {
        println!();
        println!(
            "{} {} ({} errors, {} warnings, {} info, {} hints)",
            "Found".bold(),
            format!("{} issues", total).bold(),
            total_errors.to_string().red().bold(),
            total_warnings.to_string().yellow().bold(),
            total_info.to_string().blue(),
            total_hints.to_string().dimmed()
        );
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
    if total_errors > 0 {
        ExitCode::from(1)
    } else if args.error_on_warnings && total_warnings > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
