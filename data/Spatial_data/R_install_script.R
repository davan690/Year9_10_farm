# R Package Installation Script
# This script installs all packages needed for data analysis, 
# reproducible reports, and Shiny dashboards

# Function to install packages if not already installed
install_if_missing <- function(packages) {
  new_packages <- packages[!(packages %in% installed.packages()[,"Package"])]
  if(length(new_packages) > 0) {
    cat("Installing:", paste(new_packages, collapse = ", "), "\n")
    install.packages(new_packages, dependencies = TRUE)
  } else {
    cat("All packages already installed.\n")
  }
}

# Core tidyverse and data manipulation
core_packages <- c(
  "tidyverse",      # Data manipulation and visualization
  "dplyr",          # Data manipulation
  "ggplot2",        # Data visualization
  "tidyr",          # Data tidying
  "readr",          # Reading data
  "purrr",          # Functional programming
  "tibble",         # Modern data frames
  "stringr",        # String manipulation
  "forcats",        # Factor handling
  "lubridate",      # Date and time handling
  "data.table"      # Fast data manipulation
)

# Reporting and documentation
reporting_packages <- c(
  "rmarkdown",      # R Markdown documents
  "knitr",          # Dynamic report generation
  "bookdown",       # Authoring books and long documents
  "pagedown",       # Paged HTML documents
  "xaringan",       # Presentation slides
  "tinytex",        # LaTeX distribution
  "kableExtra",     # Enhanced tables
  "gt",             # Grammar of tables
  "flextable",      # Flexible tables
  "DT",             # Interactive tables
  "reactable"       # Interactive data tables
)

# Shiny and dashboard development
shiny_packages <- c(
  "shiny",          # Shiny web applications
  "shinydashboard", # Dashboard layouts
  "shinyWidgets",   # Additional Shiny widgets
  "shinythemes",    # Shiny themes
  "shinyjs",        # JavaScript operations in Shiny
  "shinyBS",        # Bootstrap components
  "shinycssloaders", # Loading animations
  "shinyvalidate",  # Input validation
  "bslib",          # Bootstrap themes
  "thematic",       # Unified theming
  "plotly",         # Interactive plots
  "leaflet",        # Interactive maps
  "htmlwidgets"     # HTML widgets framework
)

# Data import/export
io_packages <- c(
  "readxl",         # Read Excel files
  "writexl",        # Write Excel files
  "haven",          # SPSS, Stata, SAS files
  "jsonlite",       # JSON data
  "xml2",           # XML data
  "httr",           # HTTP requests
  "rvest",          # Web scraping
  "RSQLite",        # SQLite databases
  "odbc",           # Database connectivity
  "DBI"             # Database interface
)

# Spatial data and mapping
spatial_packages <- c(
  "sf",             # Simple features for spatial data
  "sp",             # Spatial data classes
  "raster",         # Raster data
  "terra",          # Modern spatial data
  "mapview",        # Interactive viewing
  "tmap",           # Thematic maps
  "rgdal",          # Geospatial abstraction library
  "leaflet.extras", # Additional leaflet features
  "geosphere"       # Spherical trigonometry
)

# Statistical analysis
stats_packages <- c(
  "broom",          # Tidy model outputs
  "modelr",         # Modeling functions
  "caret",          # Classification and regression
  "lme4",           # Mixed-effects models
  "survival",       # Survival analysis
  "car",            # Companion to applied regression
  "MASS",           # Modern applied statistics
  "psych",          # Psychological research tools
  "DescTools"       # Descriptive statistics tools
)

# Visualization
viz_packages <- c(
  "ggthemes",       # Additional ggplot2 themes
  "ggrepel",        # Text labels that don't overlap
  "gganimate",      # Animated ggplot2
  "patchwork",      # Combine ggplot2 plots
  "cowplot",        # Publication-ready plots
  "scales",         # Scale functions for visualization
  "RColorBrewer",   # Color palettes
  "viridis",        # Color-blind friendly palettes
  "gridExtra",      # Grid graphics
  "corrplot"        # Correlation plots
)

# Reproducibility and workflow
workflow_packages <- c(
  "here",           # Project-relative paths
  "renv",           # Dependency management
  "usethis",        # Project setup
  "devtools",       # Package development
  "pkgdown",        # Package documentation websites
  "testthat",       # Unit testing
  "roxygen2",       # Documentation generation
  "styler",         # Code formatting
  "lintr"           # Code linting
)

# Additional utilities
utility_packages <- c(
  "janitor",        # Data cleaning
  "glue",           # String interpolation
  "fs",             # File system operations
  "progress",       # Progress bars
  "tictoc",         # Timing code
  "assertthat",     # Assertions
  "cli",            # Command line interface
  "crayon",         # Colored terminal output
  "rlang"           # Low-level R programming
)

# Combine all package lists
all_packages <- c(
  core_packages,
  reporting_packages,
  shiny_packages,
  io_packages,
  spatial_packages,
  stats_packages,
  viz_packages,
  workflow_packages,
  utility_packages
)

# Remove duplicates
all_packages <- unique(all_packages)

# Display summary
cat("==============================================\n")
cat("R Package Installation Script\n")
cat("==============================================\n")
cat("Total packages to check:", length(all_packages), "\n")
cat("==============================================\n\n")

# Install packages
cat("Checking and installing packages...\n\n")
install_if_missing(all_packages)

# Install TinyTeX for PDF rendering (optional)
cat("\n==============================================\n")
cat("Installing TinyTeX for PDF rendering...\n")
cat("This is optional but recommended for R Markdown PDFs\n")
cat("==============================================\n")
if (!tinytex::is_tinytex()) {
  response <- readline(prompt = "Install TinyTeX? (y/n): ")
  if (tolower(response) == "y") {
    tinytex::install_tinytex()
    cat("TinyTeX installed successfully!\n")
  }
}

# Verify installation
cat("\n==============================================\n")
cat("Verifying installation...\n")
cat("==============================================\n")
installed <- all_packages[all_packages %in% installed.packages()[,"Package"]]
not_installed <- all_packages[!(all_packages %in% installed.packages()[,"Package"])]

cat("\nSuccessfully installed:", length(installed), "packages\n")
if (length(not_installed) > 0) {
  cat("\nFailed to install the following packages:\n")
  cat(paste(not_installed, collapse = "\n"), "\n")
  cat("\nYou may need to install these manually.\n")
} else {
  cat("\nAll packages installed successfully!\n")
}

cat("\n==============================================\n")
cat("Installation complete!\n")
cat("You can now start building reproducible reports\n")
cat("and Shiny dashboards.\n")
cat("==============================================\n")

