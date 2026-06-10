# TinyMCE Migration Notes

This build migrates the official signal drafting body field to TinyMCE.

## Added
- TinyMCE Cloud script loading on the signal creation page only.
- Controlled operational toolbar: undo/redo, bold, italic, underline, alignment, bullets, numbering, table, remove formatting.
- Table support inside signal text.
- Word count/status bar.
- Responsive editor styling for desktop, tablet, and phone.
- Form validation updated so TinyMCE content is saved back into the hidden textarea before submit.

## Preserved
- Official NAF signal print template.
- Print preview and PDF/export flow.
- Personnel watermarking.
- Audit logging.
- Role-based access: View-Only Officers still cannot access the editor.
- Sanitized HTML storage using existing backend sanitization.

## Security Discipline
The editor does not enable image upload, media embedding, arbitrary fonts, color picker, or external embeds.
