#!/usr/bin/env python3
"""Interactive, secure AI provider setup for native and Docker installs."""
import argparse
import getpass
import os
from pathlib import Path
from urllib.parse import urlparse

PROVIDERS = ('ollama', 'openai', 'azure_openai', 'anthropic')
KEYS = ('LEXIGRID_AI_PROVIDER', 'LEXIGRID_AI_MODEL', 'LEXIGRID_AI_ENDPOINT',
        'LEXIGRID_AI_AIRGAPPED', 'LEXIGRID_AI_ALLOW_CLOUD',
        'LEXIGRID_AI_LOCAL_HOSTS', 'LEXIGRID_AI_API_KEY')
DEFAULT_MODELS = {'ollama':'qwen2.5:7b', 'openai':'gpt-4o-mini',
                  'azure_openai':'gpt-4o-mini', 'anthropic':'claude-sonnet-4-5'}
DEFAULT_ENDPOINTS = {'openai':'https://api.openai.com',
                     'anthropic':'https://api.anthropic.com'}

def load(path):
    result={}
    if path.exists():
        for line in path.read_text().splitlines():
            if line and not line.startswith('#') and '=' in line:
                k,v=line.split('=',1);result[k]=v
    return result

def ask(label, default):
    response=input(f'{label} [{default}]: ').strip()
    return response or default

def configure(path, mode, interactive=True):
    original=path.read_text() if path.exists() else ''
    existing=load(path)
    if not interactive and all(k in existing for k in KEYS[:5]):
        print('Existing AI configuration retained.');return
    if interactive:
        print('\nAI provider setup (local Ollama is the default).')
        print('  1) Ollama (local-only / air-gapped)')
        print('  2) OpenAI (cloud; explicit opt-in)')
        print('  3) Azure OpenAI (cloud; explicit opt-in)')
        print('  4) Anthropic Claude (cloud; explicit opt-in)')
        choice=ask('Choose provider 1-4', str(PROVIDERS.index(existing.get('LEXIGRID_AI_PROVIDER','ollama'))+1) if existing.get('LEXIGRID_AI_PROVIDER','ollama') in PROVIDERS else '1')
        provider={'1':'ollama','2':'openai','3':'azure_openai','4':'anthropic'}.get(choice)
        if not provider: raise ValueError('Invalid provider selection')
    else:
        provider=existing.get('LEXIGRID_AI_PROVIDER','ollama')
    if provider not in PROVIDERS: raise ValueError('Invalid provider')
    local=provider=='ollama'
    model_default=existing.get('LEXIGRID_AI_MODEL') if existing.get('LEXIGRID_AI_PROVIDER')==provider else None
    model_default=model_default or DEFAULT_MODELS[provider]
    endpoint_default=(existing.get('LEXIGRID_AI_ENDPOINT') if existing.get('LEXIGRID_AI_PROVIDER')==provider else None) or (
        'http://host.docker.internal:11434' if mode=='docker' else 'http://127.0.0.1:11434') if local else (
        (existing.get('LEXIGRID_AI_ENDPOINT') if existing.get('LEXIGRID_AI_PROVIDER')==provider else None) or DEFAULT_ENDPOINTS.get(provider,'https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT/chat/completions?api-version=2024-10-21'))
    if interactive:
        model=ask('Model identifier (Azure: deployment model name)', model_default)
        endpoint=ask('Provider endpoint', endpoint_default)
    else:
        model=model_default;endpoint=endpoint_default
    parsed=urlparse(endpoint)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Invalid endpoint URL')
    if local:
        if parsed.hostname not in ('127.0.0.1','localhost','::1','host.docker.internal'):
            raise ValueError('Ollama endpoint must use an approved local hostname')
        if mode=='docker' and parsed.hostname in ('127.0.0.1','localhost'):
            print('WARNING: Docker localhost refers to the container, not the Mac host.')
    else:
        if parsed.scheme!='https': raise ValueError('Cloud AI requires HTTPS')
        if provider=='openai' and parsed.hostname!='api.openai.com': raise ValueError('OpenAI endpoint must be api.openai.com')
        if provider=='anthropic' and parsed.hostname!='api.anthropic.com': raise ValueError('Anthropic endpoint must be api.anthropic.com')
        if provider=='azure_openai' and not parsed.hostname.endswith('.openai.azure.com'): raise ValueError('Azure endpoint must be *.openai.azure.com')
        if interactive:
            confirmation=input('Cloud AI transmits risk data to an external provider. Type ENABLE CLOUD to authorize: ').strip()
            if confirmation!='ENABLE CLOUD': raise ValueError('Cloud AI not authorized')
        else:
            raise ValueError('Unattended cloud AI setup is not supported; configure securely after installation')
    secret=existing.get('LEXIGRID_AI_API_KEY','') if existing.get('LEXIGRID_AI_PROVIDER')==provider else ''
    if not local and interactive:
        entered=getpass.getpass('Provider API key (hidden; Enter retains existing key): ').strip()
        secret=entered or secret
        if not secret: raise ValueError('Cloud provider API key is required')
    new={'LEXIGRID_AI_PROVIDER':provider,'LEXIGRID_AI_MODEL':model,
         'LEXIGRID_AI_ENDPOINT':endpoint,'LEXIGRID_AI_AIRGAPPED':'1' if local else '0',
         'LEXIGRID_AI_ALLOW_CLOUD':'0' if local else '1',
         'LEXIGRID_AI_LOCAL_HOSTS': '127.0.0.1,localhost,::1,host.docker.internal' if mode=='docker' else '127.0.0.1,localhost,::1',
         'LEXIGRID_AI_API_KEY':secret if not local else ''}
    lines=[line for line in original.splitlines() if not any(line.startswith(k+'=') for k in KEYS)]
    lines+=['# AI provider configuration (administrator managed)']+[k+'='+new[k] for k in KEYS]
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.ai-tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            f.write('\n'.join(lines)+'\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        if os.name!='nt': path.chmod(0o600)
    finally:
        tmp.unlink(missing_ok=True)
    print(f'AI configured: {provider} / {model} | local-only={local}. Credentials are not displayed.')
    if local: print('Install Ollama separately, then run: ollama pull '+model)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mode',choices=['native','docker'],required=True)
    parser.add_argument('--config',type=Path,required=True)
    args=parser.parse_args()
    configure(args.config,args.mode,interactive=os.isatty(0))
if __name__=='__main__': main()
