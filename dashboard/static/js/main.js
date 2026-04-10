document.addEventListener("DOMContentLoaded", () => {
  console.log("BluJay Dashboard JS loaded.");

  const form = document.getElementById("scanForm");
  if (!form) return;

  const dirInput = document.getElementById("source_dir");
  const langSelect = document.getElementById("language");

  form.addEventListener("submit", async (e) => {
    // If a folder was selected, zip it client-side and upload via fetch.
    if (dirInput && dirInput.files && dirInput.files.length > 0) {
      e.preventDefault();

      if (!window.JSZip) {
        alert("Folder upload requires JSZip. Please contact the admin.");
        return;
      }

      try {
        // Build the zip with relative paths preserved
        const zip = new JSZip();
        const files = Array.from(dirInput.files);
        if (files.length === 0) {
          alert("Selected folder is empty.");
          return;
        }

        // Determine a nice root folder name for the zip
        let rootName = "project";
        const firstRel = files[0].webkitRelativePath || files[0].name;
        if (firstRel && firstRel.includes("/")) {
          rootName = firstRel.split("/")[0];
        }

        // Add each file under its webkitRelativePath (preserves folder structure)
        for (const file of files) {
          const relPath = file.webkitRelativePath || file.name;
          zip.file(relPath, file);
        }

        // Generate the zip blob
        const blob = await zip.generateAsync({
          type: "blob",
          compression: "DEFLATE",
          compressionOptions: { level: 6 },
        });

        // Build form data that mirrors your /scan expectations
        const fd = new FormData();
        fd.append("language", (langSelect?.value || "").toLowerCase());
        // IMPORTANT: send as "source_file" so your backend handles it the same as a normal upload
        fd.append("source_file", blob, `${rootName}.zip`);

        // POST to /scan; follow redirect to /results/<job_id>
        const res = await fetch(form.action || form.getAttribute("action") || "{{ url_for('dashboard.run_scan') }}", {
          method: "POST",
          body: fd,
          redirect: "follow",
        });

        // If Flask redirected, land on the results page
        if (res.redirected) {
          window.location.href = res.url;
          return;
        }

        // If no redirect (e.g., validation error), render server response
        const html = await res.text();
        document.open();
        document.write(html);
        document.close();
      } catch (err) {
        console.error("Folder upload failed:", err);
        alert("Folder upload failed. See console for details.");
      }
    }
    // else: normal submit for single-file uploads (zip/jar/java/py)
    // no preventDefault -> browser posts the form normally
  });
});
