package monitor

import (
	"context"
	jsonv1 "encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigUsesDefaultPathAndInitializesNotifier(t *testing.T) {
	config, err := loadConfig(context.Background(), "", func(path string) ([]byte, error) {
		require.Equal(t, DefaultConfigFile, path)
		return []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.example/topic","auth":"secret"}}}`), nil
	})
	require.NoError(t, err)
	app, err := InitializeApp(context.Background(), config)
	require.NoError(t, err)
	notifier, ok := app.Notifier.(*NotificationManager)
	require.True(t, ok)
	require.Equal(t, "Bearer secret", notifier.NtfyAuth)
}

func TestLegacyMigrationRetainsDNSRecordsWhenDomainChanges(t *testing.T) {
	input := []byte(`{"domains":[{"domain":"example.com","name":"Example","expected_registrar_id":"123"}],"dns_records":[{"hostname":"example.com","name":"web","type":"A","expected":["192.0.2.1"]}]}`)
	output, err := migrateV3Config(input)
	require.NoError(t, err)
	var root map[string]jsonv1.RawMessage
	require.NoError(t, jsonv1.Unmarshal(output, &root))
	require.Contains(t, string(root["domains"]), `"registrar":"123"`)
	require.Contains(t, string(root["dns_records"]), `"web"`)
}

func TestLegacyMigrationReportsEncodingFailures(t *testing.T) {
	input := []byte(`{"domains":[{"domain":"example.com","expected_registrar_id":"123"}],"dns_records":[{"hostname":"example.com"}]}`)
	for _, failOnCall := range []int{1, 2} {
		calls := 0
		_, err := migrateV3ConfigWithMarshal(input, func(value any) ([]byte, error) {
			calls++
			if calls == failOnCall {
				return nil, errors.New("encoding unavailable")
			}
			return jsonv1.Marshal(value)
		})
		require.ErrorContains(t, err, "encoding unavailable")
		require.Equal(t, failOnCall, calls)
	}
}

func TestEmbeddedEmailProviderLoaderReportsSourceFailures(t *testing.T) {
	_, err := loadEmailProvidersFromFS("", rejectingSubFS{})
	require.Error(t, err)
	bad := fstest.MapFS{"data/email_providers/broken.json": &fstest.MapFile{Data: []byte("{")}}
	_, err = loadEmailProvidersFromFS("", bad)
	require.Error(t, err)
}

type rejectingSubFS struct{}

func (rejectingSubFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }
func (rejectingSubFS) Sub(string) (fs.FS, error) {
	return nil, errors.New("embedded subtree unavailable")
}

func TestConfigRejectsInvalidResolverAndDomain(t *testing.T) {
	_, err := compileRawConfig(RawConfig{Resolvers: []string{"[::1"}})
	require.ErrorContains(t, err, "resolver")
	_, err = compileRawConfig(RawConfig{Domains: []DomainConfig{{Domain: "bad domain", Name: "Bad"}}})
	require.Error(t, err)
}

func TestCAAExplicitDenyAllGeneratesAllThreeChecks(t *testing.T) {
	config, err := compileRawConfig(RawConfig{Domains: []DomainConfig{{
		Domain: "example.com", Name: "Example",
		CAA: &CAAConfig{Issue: []string{}, IssueWild: []string{}, IssueMail: []string{}},
	}}})
	require.NoError(t, err)
	require.Len(t, config.DNSRecords, 1)
	require.ElementsMatch(t, []string{CAARecordIssueDenyAll, CAARecordIssueWildDenyAll, CAARecordIssueMailDenyAll}, []string(config.DNSRecords[0].Expected))
}

func TestExpectedDNSNormalizationHandlesEmptyAndMismatchedValues(t *testing.T) {
	for _, record := range []DNSTask{
		{Hostname: "example.com", Name: "a", Type: RecordTypeA, Expected: StringList{""}},
		{Hostname: "example.com", Name: "caa", Type: RecordTypeCAA, Expected: StringList{" "}},
	} {
		require.NoError(t, normalizeDNSTaskExpected(&record))
		require.Empty(t, record.Expected)
	}
	_, err := normalizeExpectedDNSValue(DNSTask{Hostname: "example.com", Type: RecordTypeCAA}, `0 issue "ca.example"`)
	require.NoError(t, err)
	_, err = normalizeExpectedDNSValue(DNSTask{Hostname: "example.com", Type: RecordTypeCAA}, "0 issue")
	require.Error(t, err)
	got, err := normalizeExpectedDNSValue(DNSTask{Type: RecordTypeCNAME}, "192.0.2.1")
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1", got)
	_, err = normalizeExpectedIPValue(DNSTask{Hostname: "example.com", Name: "a", Type: RecordTypeA}, "invalid", nil)
	require.Error(t, err)
}

func TestEmailProviderReaderReportsUnderlyingReadFailure(t *testing.T) {
	filesystem := fstest.MapFS{"broken.json": &fstest.MapFile{Data: []byte("ignored")}}
	provider, err := readEmailProvider(readErrorFS{FS: filesystem}, "broken.json")
	require.Empty(t, provider.MXRecords)
	require.Error(t, err)
}

func TestLegacyEmailMigrationReportsInvalidRawField(t *testing.T) {
	domain := map[string]jsonv1.RawMessage{
		"domain":               jsonv1.RawMessage(`"example.com"`),
		"check_email_security": jsonv1.RawMessage(`true`),
		"mx_records":           jsonv1.RawMessage(`{invalid`),
	}
	_, err := migrateV3Domain(domain)
	require.Error(t, err)
}

func TestEmailProviderLoaderSkipsDirectoriesAndNonJSONFiles(t *testing.T) {
	filesystem := fstest.MapFS{
		"README.txt":       &fstest.MapFile{Data: []byte("ignored")},
		"nested/file.json": &fstest.MapFile{Data: []byte(`{"mx_records":["mx.example"]}`)},
	}
	providers := make(map[string]ProviderConfig)
	require.NoError(t, readEmailProviders(filesystem, providers))
	require.Empty(t, providers)
}

func TestDefaultEmailProvidersSurviveMissingOverrideDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	providers, err := loadEmailProviders("")
	require.NoError(t, err)
	require.NotEmpty(t, providers)
	_, statErr := os.Stat(DefaultEmailProvidersDir)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

type readErrorFS struct{ fs.FS }

func (f readErrorFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return readErrorFile{File: file}, nil
}

type readErrorFile struct{ fs.File }

func (f readErrorFile) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
