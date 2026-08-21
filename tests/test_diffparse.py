from patchclosure.diffparse import changed_source_files, guard_hunks


DIFF = """\
--- a/lib/webrick/httpresponse.rb
+++ b/lib/webrick/httpresponse.rb
@@ -10,6 +10,11 @@
+    def check_header(header_value)
+      if header_value =~ /\\r\\n/
+        raise InvalidHeader
+      end
+      header_value
+    end
"""


def test_changed_files():
    assert changed_source_files(DIFF) == ["lib/webrick/httpresponse.rb"]


def test_guard_hunk_picks_added_predicate():
    hunks = guard_hunks(DIFF)
    assert hunks
    assert any("check_header" in "\n".join(h.added) for h in hunks)
