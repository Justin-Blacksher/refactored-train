;;; bug-bounty-mode.el --- A major mode for bug bounty hunting in Emacs -*- lexical-binding: t -*-

;; Author: Grok (inspired by bug bounty community)
;; Version: 0.1
;; Keywords: tools, hacking, bug-bounty
;; URL: None (custom mode)

;;; Commentary:
;; This mode provides a tailored environment for bug bounty hunting, including:
;; - Syntax highlighting for vulnerabilities and URLs
;; - Integration with tools like subfinder, nuclei, ffuf, and Burp Suite
;; - Automated recon pipeline for subdomain enumeration and scanning
;; - Report templates for writing professional bug bounty reports
;; - Quick access to learning resources and practice labs
;; Use M-x bug-bounty-mode or save files with .bb extension to activate.

;;; Code:

(require 'web-mode)    ;; For web-related language support
(require 'company)     ;; For autocompletion
(require 'flycheck)    ;; For syntax checking
(require 'yasnippet)   ;; For payload snippets

;;;###autoload
(define-derived-mode bug-bounty-mode fundamental-mode "BugBounty"
  "A major mode for bug bounty hunting."
  :syntax-table nil
  (setq mode-name "Bug Bounty")
  ;; Syntax highlighting for vulnerabilities and URLs
  (font-lock-add-keywords nil
                          '(("\\(XSS\\|SQLi\\|SSRF\\|IDOR\\|CSRF\\)" . font-lock-warning-face)
                            ("\\(http\\|https\\)://[^ \n]+" . font-lock-string-face)))
  ;; Enable useful minor modes
  (web-mode)
  (company-mode 1)
  (flycheck-mode 1)
  (yas-minor-mode 1)
  ;; Custom hook
  (run-hooks 'bug-bounty-mode-hook))

;; Hook for additional setup
(defun bug-bounty-mode-hook ()
  "Custom hook for bug-bounty-mode."
  (when (fboundp 'lsp)
    (lsp)) ;; Language server for code analysis
  (message "Bug Bounty Mode activated!"))

(add-hook 'bug-bounty-mode-hook 'bug-bounty-mode-hook)

;; Tool integration
(defun bug-bounty-run-subfinder (domain)
  "Run subfinder on DOMAIN and display results in a buffer."
  (interactive "sEnter domain: ")
  (let ((buffer (get-buffer-create "*BugBounty-Subfinder*")))
    (with-current-buffer buffer
      (erase-buffer)
      (shell-command (concat "subfinder -d " domain " -o -") buffer))
    (pop-to-buffer buffer)))

(defun bug-bounty-run-nuclei (urls-file)
  "Run nuclei on URLS-FILE and display results."
  (interactive "fSelect URLs file: ")
  (let ((buffer (get-buffer-create "*BugBounty-Nuclei*")))
    (with-current-buffer buffer
      (erase-buffer)
      (shell-command (concat "nuclei -l " urls-file " -t ~/nuclei-templates/") buffer))
    (pop-to-buffer buffer)))

(defun bug-bounty-open-burp ()
  "Launch Burp Suite."
  (interactive)
  (start-process "burp-suite" nil "burpsuite"))

(defun bug-bounty-recon-pipeline (domain)
  "Run a full recon pipeline on DOMAIN."
  (interactive "sEnter domain: ")
  (let ((output-dir (concat "~/bug-bounty/" domain "/"))
        (domains-file (concat "~/bug-bounty/" domain "/domains.txt"))
        (live-domains-file (concat "~/bug-bounty/" domain "/live_domains.txt")))
    (make-directory output-dir t)
    (shell-command (concat "subfinder -d " domain " > " domains-file))
    (shell-command (concat "cat " domains-file " | httpx > " live-domains-file))
    (shell-command (concat "ffuf -w ~/wordlists/common.txt -u https://FUZZ." domain "/ -o " output-dir "ffuf-output.txt"))
    (message "Recon pipeline completed. Results in %s" output-dir)))

;; Report template
(defun bug-bounty-insert-report-template ()
  "Insert a bug bounty report template in Markdown."
  (interactive)
  (insert "# Bug Bounty Report: [Vulnerability Name]

## Description
Describe the vulnerability in detail. Explain the concept and include links to resources (e.g., OWASP).

## Procedure
1. Step-by-step instructions to reproduce the bug.
2. Include tools used (e.g., Burp Suite, sqlmap).
3. Attach screenshots or code snippets.

## Impact
Explain the potential impact (e.g., data leakage, RCE).

## Fix (Optional)
Suggest a fix or mitigation.

## CVSS Score
Estimate the severity using the Common Vulnerability Scoring System.

## Program
Specify the bug bounty program (e.g., HackerOne, Bugcrowd).

## References
- [OWASP](https://owasp.org)
- [HackerOne Report Guidelines](https://hackerone.com)"))

;; Learning resources
(defun bug-bounty-open-resources ()
  "Open bug bounty learning resources."
  (interactive)
  (browse-url "https://owasp.org")
  (browse-url "https://bugbountyhunter.com")
  (browse-url "https://hackerone.com/reports"))

;; Practice lab
(defun bug-bounty-start-juice-shop ()
  "Start OWASP Juice Shop in Docker."
  (interactive)
  (shell-command "docker run --rm -p 3000:3000 bkimminich/juice-shop")
  (browse-url "http://localhost:3000"))

;; Keybindings
(define-key bug-bounty-mode-map (kbd "C-c s") 'bug-bounty-run-subfinder)
(define-key bug-bounty-mode-map (kbd "C-c n") 'bug-bounty-run-nuclei)
(define-key bug-bounty-mode-map (kbd "C-c b") 'bug-bounty-open-burp)
(define-key bug-bounty-mode-map (kbd "C-c r") 'bug-bounty-recon-pipeline)
(define-key bug-bounty-mode-map (kbd "C-c t") 'bug-bounty-insert-report-template)
(define-key bug-bounty-mode-map (kbd "C-c l") 'bug-bounty-open-resources)
(define-key bug-bounty-mode-map (kbd "C-c j") 'bug-bounty-start-juice-shop)

;; Auto-activate for .bb files
;;;###autoload
(add-to-list 'auto-mode-alist '("\\.bb\\'" . bug-bounty-mode))

;; Example yasnippet for XSS payload (requires yasnippet package)
(defun bug-bounty-define-snippets ()
  "Define snippets for bug bounty payloads."
  (yas-define-snippets 'bug-bounty-mode
                       '(("xss" "<script>alert('XSS')</script>" "XSS Payload" nil nil nil nil nil nil)
                         ("sqli" "' OR 1=1 --" "SQL Injection Payload" nil nil nil nil nil nil))))

(add-hook 'bug-bounty-mode-hook 'bug-bounty-define-snippets)

(provide 'bug-bounty-mode)
;;; bug-bounty-mode.el ends here
