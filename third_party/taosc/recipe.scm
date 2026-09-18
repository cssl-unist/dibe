;;; SPDX-FileCopyrightText: 2026 Nguyễn Gia Phong
;;; SPDX-License-Identifier: GPL-3.0-or-later

(use-modules (guix derivations)
             (guix packages)
             (guix scripts expose)
             (guix store)
             (loftix bugs)
             (srfi srfi-1))

(define bugs
  `(("CVE-2017-14940" ,binutils-2.29)
    ("CVE-2017-15025" ,binutils-2.29)
    ("CVE-2016-3623" ,libtiff-static-4.0.6)
    ("CVE-2016-10266" ,libtiff-static-4.0.7)
    ("CVE-2016-10267" ,libtiff-static-4.0.7)
    ("CVE-2017-7595" ,libtiff-static-4.0.7)
    ("CVE-2017-5980" ,zziplib-static-0.13.62)
    ("CVE-2017-5981" ,zziplib-static-0.13.62)))

(let ((args (command-line)))
  (if (= 3 (length args))
      (let* ((id (cadr args))
             (workdir (caddr args))
             (buggy-package (cadr (assoc id bugs)))
             (poc (cadr (search-bug %buggy-packages id))))
        (with-store store
          (build-things store
            (map (lambda (pkg)
                   (derivation-file-name (package-derivation store pkg)))
                 (list bux buggy-package)))
          (simple-format #t "guix time-machine ~a -- shell taosc\n"
            "-C third_party/taosc/channels.scm")
          (let ((prog (string-append (package-output store buggy-package)
                                     "/bin/" (car poc)))
                (exploit (string-append (package-output store bux)
                                        "/share/bux/" (caddr poc))))
            (simple-format #t "# PoC exploit\n~a ~a\n"
              prog
              (simple-format #f (cadr poc) exploit))
            (simple-format #t "# Patch generation\ntaosc-fix 10 ~a ~a ~a ~a\n"
              workdir
              (dirname exploit)
              prog
              (simple-format #f (cadr poc) "@@"))
            (simple-format #t "# Launch exploit with DIBE\n~a ~a ~a\n"
              "DIBE_PIDFILE=./pidfile DIBE_START_GATE=1 LD_PRELOAD=./patcher.so"
              prog
              (simple-format #f (cadr poc) exploit))
            (display "# On another shell\n")
            (simple-format #t "# Coordinate PID\nprintf ~a ~a > ~a\n"
              "'{\"pid\": %d}\\n'" "$(< ./pidfile)" "micro_patch.json")
            (simple-format #t "# Send patch\n./e9patch < ~a/~a.brpatched.json\n"
              workdir (basename prog))
            (simple-format #t "# Apply patch\necho APPLY > /tmp/dibe_ctrl.~a\n"
              "$(< ./pidfile)"))))
      (begin
         (simple-format #t "Usage: ~a BUG-ID WORKDIR\n\n" (car args))
         (simple-format #t "BUG-ID is one of the following:\n")
         (for-each (lambda (bug)
                     (format #t "~a\n" (car bug)))
                   bugs)
         (exit 1))))
