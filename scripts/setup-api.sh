#!/bin/bash
# T3MP3ST API Key Setup Script

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           T3MP3ST API KEY CONFIGURATION                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

ENV_FILE="$HOME/.t3mp3st/.env"
mkdir -p "$(dirname "$ENV_FILE")"

if [ -f "$ENV_FILE" ]; then
    echo "[*] Existing T3MP3ST env file found; it will be replaced after you enter a new key."
fi

echo ""
echo "Choose your LLM provider:"
echo "  1) OpenRouter (recommended - access to all models)"
echo "  2) Anthropic (Claude direct)"
echo "  3) OpenAI (GPT models)"
echo ""

read -p "Enter choice [1-3]: " choice

case $choice in
    1)
        echo ""
        echo "Get your OpenRouter API key at: https://openrouter.ai/keys"
        read -p "Enter your OpenRouter API key: " api_key
        echo "OPENROUTER_API_KEY=$api_key" > "$ENV_FILE"
        echo "LLM_PROVIDER=openrouter" >> "$ENV_FILE"
        ;;
    2)
        echo ""
        echo "Get your Anthropic API key at: https://console.anthropic.com/"
        read -p "Enter your Anthropic API key: " api_key
        echo "ANTHROPIC_API_KEY=$api_key" > "$ENV_FILE"
        echo "LLM_PROVIDER=anthropic" >> "$ENV_FILE"
        ;;
    3)
        echo ""
        echo "Get your OpenAI API key at: https://platform.openai.com/api-keys"
        read -p "Enter your OpenAI API key: " api_key
        echo "OPENAI_API_KEY=$api_key" > "$ENV_FILE"
        echo "LLM_PROVIDER=openai" >> "$ENV_FILE"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

chmod 600 "$ENV_FILE"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              CONFIGURATION COMPLETE!                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Your API key has been saved to $ENV_FILE (mode 600)"
echo ""
echo "Start the server with:"
echo "  npm run server"
echo ""
