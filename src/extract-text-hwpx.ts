import AdmZip from "adm-zip";

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function extractTextFromXml(xml: string): string {
  const paragraphs: string[] = [];

  const paraRe = /<hp:p[\s>][\s\S]*?<\/hp:p>/g;
  for (const pm of xml.matchAll(paraRe)) {
    const paraBlock = pm[0];
    const runs: string[] = [];

    const tRe = /<hp:t[^>]*>([\s\S]*?)<\/hp:t>/g;
    for (const tm of paraBlock.matchAll(tRe)) {
      runs.push(decodeXmlEntities(tm[1]));
    }

    if (runs.length > 0) {
      paragraphs.push(runs.join(""));
    }
  }

  return paragraphs.join("\n");
}

/**
 * Extract all text from an HWPX file buffer (decrypted or not).
 *
 * Reads Contents/section*.xml files and extracts text from <hp:t> elements.
 */
export function extractTextHwpx(input: Buffer): string {
  const zip = new AdmZip(input);
  const allTexts: string[] = [];

  const sectionEntries = zip
    .getEntries()
    .filter((e) => /^Contents\/section\d+\.xml$/i.test(e.entryName))
    .sort((a, b) => a.entryName.localeCompare(b.entryName));

  for (const entry of sectionEntries) {
    const xml = entry.getData().toString("utf-8");
    const text = extractTextFromXml(xml);
    if (text) allTexts.push(text);
  }

  return allTexts.join("\n");
}
