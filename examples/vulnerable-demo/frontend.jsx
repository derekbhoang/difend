export function ProfilePreview({ html }) {
  return <section dangerouslySetInnerHTML={{ __html: html }} />;
}

export function RedirectButton({ nextUrl }) {
  return <button onClick={() => { window.location = nextUrl; }}>Continue</button>;
}
