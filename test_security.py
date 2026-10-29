import unittest
import os
import re

class TestDocumentSecurity(unittest.TestCase):
    def setUp(self):
        self.md_files = []
        for root, dirs, files in os.walk('.'):
            # Skip hidden directories like .git
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for f in files:
                if f.endswith('.md'):
                    self.md_files.append(os.path.join(root, f))

    def remove_code_blocks(self, content):
        # Remove code blocks so we don't flag examples
        content = re.sub(r'```.*?```', '', content, flags=re.DOTALL)
        content = re.sub(r'`[^`\n]+`', '', content)
        return content

    def test_no_script_tags(self):
        """Audit for contributor submission sanitization (no script tags)."""
        for md_file in self.md_files:
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()
                content = self.remove_code_blocks(content)
                self.assertFalse(re.search(r'<script\b', content, re.IGNORECASE), f"Script tag found in {md_file}")
                self.assertFalse(re.search(r'javascript:', content, re.IGNORECASE), f"Javascript protocol found in {md_file}")
                self.assertFalse(re.search(r'\bon\w+\s*=', content, re.IGNORECASE), f"Inline event handler found in {md_file}")

    def test_template_variable_interpolation(self):
        """Audit document template variable interpolation."""
        for md_file in self.md_files:
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()
                content = self.remove_code_blocks(content)
                self.assertFalse(re.search(r'\{\{.*?\}\}', content), f"Unintended template variable interpolation ({{}}) found in {md_file}")
                self.assertFalse(re.search(r'\$\{.*?\}', content), f"Unintended template variable interpolation (${{}}) found in {md_file}")

    def test_external_link_integrity(self):
        """External link integrity checks."""
        for md_file in self.md_files:
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()
                content = self.remove_code_blocks(content)
                urls = re.findall(r'https?://[^\s)\]"\']+', content)
                for url in urls:
                    self.assertTrue(re.match(r'^https?://[a-zA-Z0-9.-]+(?:[/?:][^\s)\]"\']*)?$', url), f"Invalid external link format: {url}")

if __name__ == '__main__':
    unittest.main()
