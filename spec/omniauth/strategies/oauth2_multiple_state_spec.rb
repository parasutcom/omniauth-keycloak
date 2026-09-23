require 'spec_helper'

RSpec.describe OmniAuth::Strategies::OAuth2MultipleState do
  let(:request) { double('Request', params: {}, cookies: {}, env: {}) }
  let(:app) { -> { [200, {}, ['Hello.']] } }

  subject do
    OmniAuth::Strategies::OAuth2MultipleState.new(app, 'client_id', 'client_secret', {
                                                    client_options: {
                                                      site: 'https://example.com',
                                                      authorize_url: '/oauth/authorize',
                                                      token_url: '/oauth/token'
                                                    }
                                                  }).tap do |strategy|
      allow(strategy).to receive(:request) { request }
    end
  end

  describe '#client' do
    it 'has the correct client options' do
      expect(subject.client.site).to eq('https://example.com')
      expect(subject.client.options[:authorize_url]).to eq('/oauth/authorize')
      expect(subject.client.options[:token_url]).to eq('/oauth/token')
    end
  end

  describe '#authorize_params' do
    before do
      states = (1..5).map { |i| "state#{i}" }
      origins = (1..5).map { |i| ["state#{i}", 'origin'] }.to_h
      verifiers = (1..5).map { |i| ["state#{i}", "verifier#{i}"] }.to_h

      allow(subject).to receive(:session).and_return({
                                                       'omniauth.origin' => 'origin',
                                                       'omniauth.states' => states,
                                                       'omniauth.state_origins' => origins,
                                                       'pkce.code_verifiers' => verifiers
                                                     })

      allow(subject).to receive(:env).and_return({})
      subject.options.authorize_params = {}
    end

    it 'includes the state parameter' do
      allow(SecureRandom).to receive(:hex).and_return('state123')
      expect(subject.authorize_params[:state]).to eq('state123')
    end

    it 'trims omniauth.states to the last 3 entries' do
      allow(SecureRandom).to receive(:hex).and_return('state6')
      subject.authorize_params

      expect(subject.session['omniauth.states']).to eq(%w[state4 state5 state6])
    end

    it 'does not keep the origin in the session' do
      allow(SecureRandom).to receive(:hex).and_return('state6')
      subject.authorize_params

      expect(subject.session).not_to have_key('omniauth.state_origins')
      expect(subject.session).not_to have_key('omniauth.origin')
    end

    it 'drops the legacy single pkce.code_verifier' do
      subject.session['pkce.code_verifier'] = 'legacy_verifier'
      allow(SecureRandom).to receive(:hex).and_return('state6')
      subject.authorize_params

      expect(subject.session).not_to have_key('pkce.code_verifier')
    end

    it 'trims omniauth.state_kc_actions to the last 3 entries' do
      subject.session['omniauth.state_kc_actions'] = (1..5).map { |i| ["state#{i}", 'delete_credential:x'] }.to_h
      subject.options.authorize_params = { kc_action: 'delete_credential:x' }
      allow(SecureRandom).to receive(:hex).and_return('state6')
      subject.authorize_params

      expect(subject.session['omniauth.state_kc_actions'].keys).to eq(%w[state4 state5 state6])
    end

    it 'stores the pkce code_verifier keyed by state, not a single shared key' do
      allow(SecureRandom).to receive(:hex).and_return('state6')
      subject.authorize_params

      expect(subject.session['pkce.code_verifiers']['state6']).to be_a(String)
      # the previously-stored verifiers for other in-flight states must survive
      expect(subject.session['pkce.code_verifiers']['state5']).to eq('verifier5')
    end

    it 'does not clobber an in-flight verifier when a second authorize request starts before the first callback returns' do
      allow(SecureRandom).to receive(:hex).and_return('state_a')
      subject.authorize_params
      first_verifier = subject.session['pkce.code_verifiers']['state_a']

      allow(SecureRandom).to receive(:hex).and_return('state_b')
      subject.authorize_params

      expect(subject.session['pkce.code_verifiers']['state_a']).to eq(first_verifier)
      expect(subject.session['pkce.code_verifiers']['state_b']).not_to eq(first_verifier)
    end

    it 'trims pkce.code_verifiers to the last 3 entries' do
      allow(SecureRandom).to receive(:hex).and_return('state6')
      subject.authorize_params

      expect(subject.session['pkce.code_verifiers'].keys).to eq(%w[state4 state5 state6])
    end

    it 'drops verifiers and kc_actions whose state is no longer pending' do
      subject.session['pkce.code_verifiers']['orphan'] = 'orphan_verifier'
      subject.session['omniauth.state_kc_actions'] = { 'orphan' => 'delete_credential:x', 'state5' => 'UPDATE_PASSWORD' }
      allow(SecureRandom).to receive(:hex).and_return('state6')
      subject.authorize_params

      expect(subject.session['pkce.code_verifiers'].keys).to eq(%w[state4 state5 state6])
      expect(subject.session['omniauth.state_kc_actions']).to eq('state5' => 'UPDATE_PASSWORD')
    end
  end

  describe '#request_phase' do
    before do
      allow(subject).to receive(:session).and_return({
                                                       'omniauth.states' => []
                                                     })
    end

    it 'redirects to the authorize URL' do
      allow(SecureRandom).to receive(:hex).and_return('state6')
      allow(subject).to receive(:callback_url).and_return('https://example.com/callback')
      encoded_url = CGI.escape('https://example.com/callback')
      expect(subject).to receive(:redirect).with("https://example.com/oauth/authorize?client_id=client_id&redirect_uri=#{encoded_url}&response_type=code&state=state6")
      subject.request_phase
    end
  end

  describe '#callback_phase' do
    let(:request) { instance_double('ActionDispatch::Request', params: { 'state' => 'state123', 'code' => 'auth_code' }) }
    let(:env) { {} }

    before do
      allow(subject).to receive(:request).and_return(request)
      allow(subject).to receive(:session).and_return({
        'omniauth.states' => ['state123']
      })
      allow(subject).to receive(:env).and_return(env)
    end

    it 'does not restore omniauth.origin from a leftover omniauth.state_origins' do
      allow(subject).to receive(:session).and_return({
        'omniauth.states' => ['state123'],
        'omniauth.state_origins' => { 'state123' => 'https://example.com/kullanici-girisi' }
      })
      allow(subject).to receive(:build_access_token).and_return(double('access_token', expired?: false))
      allow(subject).to receive(:auth_hash).and_return({})
      allow(subject).to receive(:call_app!)

      subject.callback_phase

      expect(env).not_to have_key('omniauth.origin')
    end

    context 'when state does not match' do
      it 'calls fail! with :csrf_detected' do
        allow(subject).to receive(:session).and_return({
          'omniauth.states' => ['invalid_state']
        })
    
        expect(subject).to receive(:fail!).with(
          :csrf_detected,
          hash_including(
            error: "csrf_detected",
            error_description: "CSRF detected"
          )
        )
    
        subject.callback_phase
      end
    end
  end
end
