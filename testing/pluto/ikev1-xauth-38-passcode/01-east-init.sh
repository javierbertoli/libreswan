/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair send_xauth_passcode
ipsec add xauth-road-eastnet
echo "initdone"
