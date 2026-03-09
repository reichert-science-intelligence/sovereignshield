# Deploy SovereignShield to HuggingFace Spaces

## 1. Create Space

1. Go to [huggingface.co/spaces](https://huggingface.co/spaces)
2. **Create new Space**
3. Name: `sovereignshield` (or `rreichert-sovereignshield`)
4. **SDK**: Docker
5. **Visibility**: Public or Private

## 2. Push code

Clone the new Space, copy sovereignshield files to root, push:

```bash
git clone https://huggingface.co/spaces/rreichert/sovereignshield
cd sovereignshield
# Copy app.py, core/, agents/, rag/, requirements.txt, Dockerfile, README.md
# From: Artifacts/project/sovereignshield/
git add .
git commit -m "Initial SovereignShield deploy"
git push
```

Or: copy this folder contents into the Space repo root.

## 3. Add secrets

In Space **Settings → Repository secrets** add:

- `ANTHROPIC_API_KEY`
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`

## 4. Build & run

HF rebuilds on push. Visit `https://rreichert-sovereignshield.hf.space` when ready.
