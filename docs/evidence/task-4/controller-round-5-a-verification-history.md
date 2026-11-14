# Controller A integrity verification limitations

The final archived verification command completed successfully without rerunning
tests, invoking Docker, reading the stopped scene, or claiming ordinary admission.

Two earlier controller assertions were harness mistakes, not observed product or
artifact mutations. The first assumed all176 old evidence files were0644 and
stopped at `controller-evidence-round-1-verification.json`, currently0664. Git
stores executable-bit mode, not complete historical Unix permission bits. The
corrected check compares old bytes and Git mode, and reports the current permission
histogram separately; full historical Unix permissions cannot all be reconstructed
from that Git tree. No old permissions were changed.

The second expected the new README to occur verbatim as one contiguous string in
the appended ignored report. A bounded text diff found two extra report provenance
paragraphs (`Evidence directory` and `Frozen A handoff`). The final comparison
removes only those two paragraphs and requires the remaining complete body to match.
No report or README was changed to make verification pass.

The frozen native test output records25PASS/exit0 at source dbc6d648. This controller
checked that output and hashes, without repeating the suite. Original Q5GB remains
unreleased and actual recovery, ordinary postflight and Task4 acceptance are open.
