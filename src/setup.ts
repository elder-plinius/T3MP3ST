#!/usr/bin/env node
/**
 * T3MP3ST Setup Wizard
 *
 * Interactive setup for configuring API keys and settings.
 */

import inquirer from 'inquirer';
import chalk from 'chalk';
import boxen from 'boxen';
import ora from 'ora';
import { config, AVAILABLE_MODELS, hasApiKey, setApiKey } from './config/index.js';
import { LLMBackbone } from './llm/index.js';
import { getBanner } from './index.js';

// =============================================================================
// DISPLAY HELPERS
// =============================================================================

function showBanner(): void {
  console.log(chalk.cyan(getBanner()));
}

function showBox(title: string, content: string, borderColor: string = 'cyan'): void {
  console.log(
    boxen(content, {
      title,
      titleAlignment: 'center',
      padding: 1,
      margin: 1,
      borderStyle: 'round',
      borderColor: borderColor as any,
    })
  );
}

function showSuccess(message: string): void {
  console.log(chalk.green('✓ ') + message);
}

function showError(message: string): void {
  console.log(chalk.red('✗ ') + message);
}

function showInfo(message: string): void {
  console.log(chalk.blue('ℹ ') + message);
}

function showWarning(message: string): void {
  console.log(chalk.yellow('⚠ ') + message);
}

// =============================================================================
// API KEY SETUP
// =============================================================================

async function setupOpenRouterKey(): Promise<boolean> {
  console.log('');
  showInfo('OpenRouter provides access to multiple AI models through a single API.');
  showInfo('Get your API key at: ' + chalk.underline('https://openrouter.ai/keys'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your OpenRouter API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  // Test the API key
  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('openrouter', apiKey);
    showSuccess('OpenRouter API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupVeniceKey(): Promise<boolean> {
  console.log('');
  showInfo('Venice AI is an OpenAI-compatible, privacy-focused provider (uncensored models).');
  showInfo('Get your API key at: ' + chalk.underline('https://venice.ai/settings/api'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your Venice API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  // Test the API key
  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'venice',
      model: 'llama-3.3-70b',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('venice', apiKey);
    showSuccess('Venice API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupAnthropicKey(): Promise<boolean> {
  console.log('');
  showInfo('Anthropic provides direct access to Claude models.');
  showInfo('Get your API key at: ' + chalk.underline('https://console.anthropic.com/'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your Anthropic API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('anthropic', apiKey);
    showSuccess('Anthropic API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupDeepSeekKey(): Promise<boolean> {
  console.log('');
    showInfo('DeepSeek provides OpenAI-compatible chat and reasoning models (V4 Flash / V4 Pro).');
  showInfo('Get your API key at: ' + chalk.underline('https://platform.deepseek.com/api_keys'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your DeepSeek API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'deepseek',
      model: 'deepseek-v4-pro',
      baseUrl: 'https://api.deepseek.com',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('deepseek', apiKey);
    showSuccess('DeepSeek API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupOpenAIKey(): Promise<boolean> {
  console.log('');
  showInfo('OpenAI provides access to GPT models.');
  showInfo('Get your API key at: ' + chalk.underline('https://platform.openai.com/api-keys'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your OpenAI API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'openai',
      model: 'gpt-4-turbo-preview',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('openai', apiKey);
    showSuccess('OpenAI API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupLiteLLMProxy(): Promise<boolean> {
  console.log('');
  showInfo('LiteLLM is an AI gateway proxy that routes to 100+ LLM providers.');
  showInfo('Docs: ' + chalk.underline('https://docs.litellm.ai/docs/proxy/quick_start'));
  console.log('');

  const { baseUrl } = await inquirer.prompt([
    {
      type: 'input',
      name: 'baseUrl',
      message: 'Enter your LiteLLM proxy base URL:',
      default: 'http://localhost:4000/v1',
      validate: (input: string) => {
        if (!input || !input.startsWith('http')) {
          return 'Please enter a valid URL (e.g. http://localhost:4000/v1)';
        }
        return true;
      },
    },
  ]);

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your LiteLLM API key (leave blank if not required):',
      mask: '*',
    },
  ]);

  const { model } = await inquirer.prompt([
    {
      type: 'input',
      name: 'model',
      message: 'Enter the default model (uses LiteLLM model format, e.g. gpt-4o, anthropic/claude-sonnet-4-6):',
      default: 'gpt-4o',
    },
  ]);

  const spinner = ora('Testing LiteLLM proxy connection...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'litellm',
      model,
      apiKey: apiKey || undefined,
      baseUrl,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('LiteLLM proxy connection successful!');

    config.set('litellm', { baseUrl, defaultModel: model });
    if (apiKey) setApiKey('litellm', apiKey);
    showSuccess('LiteLLM proxy configured successfully!');

    return true;
  } catch (error) {
    spinner.fail('LiteLLM proxy connection failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);

    const { saveAnyway } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'saveAnyway',
        message: 'Save the configuration anyway? (proxy may not be running yet)',
        default: true,
      },
    ]);

    if (saveAnyway) {
      config.set('litellm', { baseUrl, defaultModel: model });
      if (apiKey) setApiKey('litellm', apiKey);
      showSuccess('LiteLLM proxy configuration saved.');
      return true;
    }
    return false;
  }
}

// =============================================================================
// MODEL SELECTION
// =============================================================================

async function selectDefaultModel(): Promise<void> {
  const provider = config.get('defaultProvider');
  const models = AVAILABLE_MODELS[provider];

  if (!models || models.length === 0) {
    showWarning('No models available for the current provider');
    return;
  }

  const { model } = await inquirer.prompt([
    {
      type: 'list',
      name: 'model',
      message: 'Select your default model:',
      choices: models.map(m => ({
        name: `${m.name} (${m.provider}) - ${m.contextWindow.toLocaleString()} tokens`,
        value: m.id,
      })),
      default: config.get('defaultModel'),
    },
  ]);

  config.setDefaultModel(provider, model);
  showSuccess(`Default model set to: ${model}`);
}

// =============================================================================
// MAIN SETUP FLOW
// =============================================================================

async function runSetup(): Promise<void> {
  showBanner();

  showBox(
    'Welcome to T3MP3ST Setup',
    `This wizard will help you configure T3MP3ST for first use.

You can use a local model with no API key, or add a key from one of these providers:
• ${chalk.cyan('Local')} - Ollama / LM Studio / vLLM via TEMPEST_LOCAL_BASE_URL
• ${chalk.cyan('OpenRouter')} (recommended) - Access multiple models
• ${chalk.cyan('Anthropic')} - Direct Claude access
• ${chalk.cyan('OpenAI')} - GPT models
• ${chalk.cyan('DeepSeek')} - OpenAI-compatible chat/reasoning models
• ${chalk.cyan('LiteLLM')} - AI gateway proxy (100+ providers)

The setup will guide you through:
1. Adding API key(s), if you use a hosted provider
2. Selecting your default provider and model
3. Configuring basic settings`,
    'cyan'
  );

  // Check existing configuration
  const hasOpenRouter = hasApiKey('openrouter');
  const hasAnthropic = hasApiKey('anthropic');
  const hasOpenAI = hasApiKey('openai');
  const hasDeepSeek = hasApiKey('deepseek');
  const hasLiteLLM = config.hasLiteLLMProxy();

  if (hasOpenRouter || hasAnthropic || hasOpenAI || hasDeepSeek || hasLiteLLM) {
    console.log('');
    showInfo('Existing API keys detected:');
    if (hasOpenRouter) showSuccess('  OpenRouter: configured');
    if (hasAnthropic) showSuccess('  Anthropic: configured');
    if (hasOpenAI) showSuccess('  OpenAI: configured');
    if (hasDeepSeek) showSuccess('  DeepSeek: configured');
    if (hasLiteLLM) showSuccess('  LiteLLM Proxy: configured');
    console.log('');

    const { action } = await inquirer.prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'Add/update API keys', value: 'keys' },
          { name: 'Change default provider/model', value: 'model' },
          { name: 'View current configuration', value: 'view' },
          { name: 'Reset all settings', value: 'reset' },
          { name: 'Exit', value: 'exit' },
        ],
      },
    ]);

    switch (action) {
      case 'keys':
        await setupApiKeys();
        break;
      case 'model':
        await setupProvider();
        await selectDefaultModel();
        break;
      case 'view':
        viewConfiguration();
        break;
      case 'reset':
        await resetConfiguration();
        break;
      case 'exit':
        return;
    }
  } else {
    // First-time setup
    await setupApiKeys();
    await setupProvider();
  }

  console.log('');
  showBox(
    'Setup Complete!',
    `T3MP3ST is now configured and ready to use.

Quick start:
${chalk.cyan('npx t3mp3st')}        Start the interactive CLI
${chalk.cyan('npx t3mp3st --help')} View all commands

Or use in your code:
${chalk.gray(`import { createTempest } from 't3mp3st';
const tempest = createTempest({ name: 'My Operation' });`)}`,
    'green'
  );
}

async function setupApiKeys(): Promise<void> {
  const { providers } = await inquirer.prompt([
    {
      type: 'checkbox',
      name: 'providers',
      message: 'Which hosted API keys would you like to configure? Leave empty to use a local model only.',
      choices: [
        {
          name: `OpenRouter ${hasApiKey('openrouter') ? chalk.green('(configured)') : chalk.yellow('(recommended)')}`,
          value: 'openrouter',
        },
        {
          name: `Venice ${hasApiKey('venice') ? chalk.green('(configured)') : ''}`,
          value: 'venice',
        },
        {
          name: `Anthropic ${hasApiKey('anthropic') ? chalk.green('(configured)') : ''}`,
          value: 'anthropic',
        },
        {
          name: `OpenAI ${hasApiKey('openai') ? chalk.green('(configured)') : ''}`,
          value: 'openai',
        },
        {
          name: `DeepSeek ${hasApiKey('deepseek') ? chalk.green('(configured)') : ''}`,
          value: 'deepseek',
        },
        {
          name: `LiteLLM Proxy ${config.hasLiteLLMProxy() ? chalk.green('(configured)') : chalk.gray('(100+ providers via gateway)')}`,
          value: 'litellm',
        },
      ],
    },
  ]);

  for (const provider of providers) {
    switch (provider) {
      case 'venice':
        await setupVeniceKey();
        break;
      case 'openrouter':
        await setupOpenRouterKey();
        break;
      case 'anthropic':
        await setupAnthropicKey();
        break;
      case 'openai':
        await setupOpenAIKey();
        break;
      case 'deepseek':
        await setupDeepSeekKey();
        break;
      case 'litellm':
        await setupLiteLLMProxy();
        break;
    }
  }
}

async function setupProvider(): Promise<void> {
  const configuredProviders = [];

  configuredProviders.push({ name: 'Local model (Ollama / LM Studio / vLLM, no API key)', value: 'local' });
  if (hasApiKey('openrouter')) configuredProviders.push({ name: 'OpenRouter', value: 'openrouter' });
  if (hasApiKey('venice')) configuredProviders.push({ name: 'Venice', value: 'venice' });
  if (hasApiKey('anthropic')) configuredProviders.push({ name: 'Anthropic', value: 'anthropic' });
  if (hasApiKey('openai')) configuredProviders.push({ name: 'OpenAI', value: 'openai' });
  if (hasApiKey('deepseek')) configuredProviders.push({ name: 'DeepSeek', value: 'deepseek' });
  if (config.hasLiteLLMProxy()) configuredProviders.push({ name: 'LiteLLM Proxy', value: 'litellm' });

  const { provider } = await inquirer.prompt([
    {
      type: 'list',
      name: 'provider',
      message: 'Select your default LLM provider:',
      choices: configuredProviders,
    },
  ]);

  config.setDefaultProvider(provider);
  showSuccess(`Default provider set to: ${provider}`);
}

function viewConfiguration(): void {
  const settings = config.getAll();

  console.log('');
  showInfo('Current Configuration:');
  console.log('');
  console.log(chalk.cyan('  Default Provider: ') + settings.defaultProvider);
  console.log(chalk.cyan('  Default Model: ') + settings.defaultModel);
  console.log(chalk.cyan('  Max Tokens: ') + settings.maxTokens);
  console.log(chalk.cyan('  Temperature: ') + settings.temperature);
  console.log('');
  console.log(chalk.cyan('  API Keys:'));
  console.log('    OpenRouter: ' + (hasApiKey('openrouter') ? chalk.green('configured') : chalk.red('not set')));
  console.log('    Venice: ' + (hasApiKey('venice') ? chalk.green('configured') : chalk.red('not set')));
  console.log('    Anthropic: ' + (hasApiKey('anthropic') ? chalk.green('configured') : chalk.red('not set')));
  console.log('    OpenAI: ' + (hasApiKey('openai') ? chalk.green('configured') : chalk.red('not set')));
  console.log('    DeepSeek: ' + (hasApiKey('deepseek') ? chalk.green('configured') : chalk.red('not set')));
  console.log('    LiteLLM Proxy: ' + (config.hasLiteLLMProxy() ? chalk.green('configured') : chalk.red('not set')));
  console.log('');
  console.log(chalk.cyan('  Config Path: ') + config.getConfigPath());
  console.log('');
}

async function resetConfiguration(): Promise<void> {
  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: 'Are you sure you want to reset all settings? This will remove all API keys.',
      default: false,
    },
  ]);

  if (confirm) {
    config.reset();
    showSuccess('All settings have been reset.');
  } else {
    showInfo('Reset cancelled.');
  }
}

// =============================================================================
// RUN
// =============================================================================

runSetup().catch(console.error);
