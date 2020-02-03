# Coding

We are using OTBS (One True Brace Style) style code formating. (https://poshcode.gitbooks.io/powershell-practice-and-style/)
Classes and variables follow PascalCase naming
Functions follow PowerShell Verb-Noun naming and should be Advanced Functions with proper CmdletBinding() parameter handling
Exported functions should be documented using comment based help (https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comment_based_help?view=powershell-7) and adding comments before the function
Code should confrim and be analyzed with PSScriptAnalyzer (https://github.com/PowerShell/PSScriptAnalyzer), exceptions should be marked in the source code.
Code should be clean and simple. Code can be analyzed for complexity metrics using PSCodeHealth (https://pscodehealth.readthedocs.io/en/latest/) see for more details (https://mathieubuisson.github.io/powershell-code-quality-pscodehealth/)
Use check.ps1 to analyze source code

# Commits

Commits should be clean (1 semantical change in one commit) and well documented in the commit message.
We are using Conventional Commits (https://www.conventionalcommits.org/en/v1.0.0/) commit messages.
Master branch must maintain linear history without merge commits