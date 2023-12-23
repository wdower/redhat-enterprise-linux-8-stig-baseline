# frozen_string_literal: true

# al: reviewed

control 'SV-230226' do
  title 'RHEL 8 must display the Standard Mandatory DoD Notice and Consent
Banner before granting local or remote access to the system via a graphical
user logon.'
  desc 'Display of a standardized and approved use notification before
granting access to the operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy. Use
the following verbiage for operating systems that can accommodate banners of
1300 characters:

    "You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details."'
  desc 'check', %q(Verify RHEL 8 displays the Standard Mandatory DoD Notice and Consent Banner
before granting access to the operating system via a graphical user logon.

    Note: This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    Check that the operating system displays the exact Standard Mandatory DoD
Notice and Consent Banner text with the command:

    $ sudo grep banner-message-text /etc/dconf/db/local.d/*

    banner-message-text=
    'You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only. \
    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:\
    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.\
    -At any time, the USG may inspect and seize data stored on this IS.\
    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.\
    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.\
    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details. '

    Note: The "\" characters are for formatting only. They will not be displayed on the
graphical interface.

    If the banner does not match the Standard Mandatory DoD Notice and Consent
Banner exactly, this is a finding.)
  desc 'fix', %q(Configure the operating system to display the Standard Mandatory DoD Notice
and Consent Banner before granting access to the system.

    Note: If the system does not have a graphical user interface installed,
this requirement is Not Applicable.

    Add the following lines to the [org/gnome/login-screen] section of the
"/etc/dconf/db/local.d/01-banner-message":

    banner-message-text='You are accessing a U.S. Government (USG) Information
System (IS) that is provided for USG-authorized use only.\
    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:\
    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.\
    -At any time, the USG may inspect and seize data stored on this IS.\
    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.\
    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.\
    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details. '

    Note: The "\" characters are for formatting only. They will not be displayed on the
graphical interface.

    Run the following command to update the database:

    $ sudo dconf update)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-230226'
  tag rid: 'SV-230226r743916_rule'
  tag stig_id: 'RHEL-08-010050'
  tag fix_id: 'F-32870r743915_fix'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  only_if("The system does not have GNOME installed, or we are in a container, this requirement is Not
        Applicable.", impact: 0.0) { package('gnome-desktop3').installed? && virtualization.system.eql?('docker') }

  describe command('grep ^banner-message-text /etc/dconf/db/local.d/*') do
    its('stdout.strip') { should cmp input('banner_message_text_gui') }
  end
end
