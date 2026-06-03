use colored::*;
use std::collections::HashMap;

use crate::scanner::ScanResult;

/// Print detected secrets with colored terminal output
pub fn print_results(results: &[ScanResult]) {
    if results.is_empty() {
        return;
    }

    // Group results by file
    let mut grouped: HashMap<&std::path::Path, Vec<&ScanResult>> = HashMap::new();
    for result in results {
        grouped.entry(result.file_path.as_path()).or_default().push(result);
    }

    // Print summary header
    let severity_counts = count_by_severity(results);
    println!();
    println!("{}", "env-alert scan results".bold().white());
    println!("{}", "━".repeat(60).dimmed());
    println!(
        " {} {}  {} {}  {} {}",
        "high:".red().bold(),
        severity_counts.get("high").unwrap_or(&0).to_string().red().bold(),
        "medium:".yellow().bold(),
        severity_counts.get("medium").unwrap_or(&0).to_string().yellow().bold(),
        "low:".cyan().bold(),
        severity_counts.get("low").unwrap_or(&0).to_string().cyan().bold(),
    );
    println!(" {} total findings", results.len().to_string().white().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // Print results grouped by file
    for (file_path, file_results) in &grouped {
        let file_count = file_results.len();
        let display_path = file_path.to_string_lossy();
        println!(" {} {}", "📁".to_string(), display_path.white().bold());
        println!("   {} {} {}", "└─".dimmed(), file_count, "finding(s)".dimmed());

        for result in file_results {
            let severity_color = match result.severity {
                "high" => "●".red(),
                "medium" => "●".yellow(),
                "low" => "●".cyan(),
                _ => "●".white(),
            };

            let entropy_str = if result.entropy >= 4.5 {
                format!("{:.1}", result.entropy).red().to_string()
            } else if result.entropy >= 3.5 {
                format!("{:.1}", result.entropy).yellow().to_string()
            } else {
                format!("{:.1}", result.entropy).dimmed().to_string()
            };

            println!(
                "   {} {}  {} {}",
                severity_color,
                format!("{}:{}:{}", result.file_path.display(), result.line_number, result.column).dimmed(),
                result.pattern_name.bold(),
                format!("[entropy={}]", entropy_str).dimmed(),
            );

            // Show the matched line with context
            let line = &result.line_content;
            if !line.is_empty() {
                let truncated: String = line.chars().take(120).collect();
                println!("      {} {}", ">".dimmed(), truncated.truecolor(180, 180, 180));
            }
        }
        println!();
    }

    // Print summary
    println!("{}", "━".repeat(60).dimmed());
    println!("{}", "Summary by category".bold().white());
    let mut category_counts: HashMap<&str, usize> = HashMap::new();
    for result in results {
        *category_counts.entry(&result.pattern_name).or_insert(0) += 1;
    }
    for (category, count) in &category_counts {
        println!("  {}: {}", category.dimmed(), count.to_string().white().bold());
    }
    println!("{}", "━".repeat(60).dimmed());
    println!();
}

/// Print a success message when no secrets are found
pub fn print_success(msg: &str) {
    println!();
    println!(" {} {}", "✓".green().bold(), msg.green());
    println!();
}

/// Output results as JSON for programmatic consumption
pub fn output_json(results: &[ScanResult]) {
    #[derive(serde::Serialize)]
    struct JsonResult {
        file: String,
        line: usize,
        column: usize,
        pattern: String,
        severity: String,
        matched: String,
        entropy: f64,
    }

    #[derive(serde::Serialize)]
    struct JsonOutput {
        findings: Vec<JsonResult>,
        total: usize,
        severity_counts: HashMap<String, usize>,
    }

    let mut output = JsonOutput {
        findings: Vec::new(),
        total: results.len(),
        severity_counts: count_by_severity(results),
    };

    for result in results {
        output.findings.push(JsonResult {
            file: result.file_path.to_string_lossy().to_string(),
            line: result.line_number,
            column: result.column,
            pattern: result.pattern_name.clone(),
            severity: result.severity.clone(),
            matched: result.matched_text.clone(),
            entropy: result.entropy,
        });
    }

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn count_by_severity(results: &[ScanResult]) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for result in results {
        *counts.entry(result.severity.clone()).or_insert(0) += 1;
    }
    counts
}
