control 'SV-230291' do
  title 'The RHEL 8 SSH daemon must not allow unused methods of authentication.'
  desc  "Configuring these settings for the SSH daemon provides additional
assurance that remote logon via SSH will not use unused methods of
authentication, even in the event of misconfiguration elsewhere."
  desc  'rationale', ''
  desc  'check', "
    Verify the SSH daemon does not allow authentication using unused methods of
authentication with the following command:

    $ sudo grep -i \"KerberosAuthentication\\|GSSAPIAuthentication\"
/etc/ssh/sshd_config

    KerberosAuthentication no
    GSSAPIAuthentication no

    If the values are returned as \"yes\", the returned line is commented out,
no output is returned, or has not been documented with the ISSO, this is a
finding.
  "
  desc 'fix', "
    Configure the SSH daemon to not allow authentication using unused methods
of authentication.

    Add the following line in \"/etc/ssh/sshd_config\", or uncomment the line
and set the value to \"no\":

    KerberosAuthentication no
    GSSAPIAuthentication no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230291'
  tag rid: 'SV-230291r627750_rule'
  tag stig_id: 'RHEL-08-010521'
  tag fix_id: 'F-32935r567620_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe "Control not applicable - SSH is not installed within containerized RHEL" do
      skip "Control not applicable - SSH is not installed within containerized RHEL"
    end
  else
    describe sshd_config do
      its('GSSAPIAuthentication') { should cmp 'no' }
    end
    describe sshd_config do
      its('KerberosAuthentication') { should cmp 'no' }
    end
  end
end
