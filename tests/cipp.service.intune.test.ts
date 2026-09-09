import { McpError } from '@modelcontextprotocol/sdk/types.js';
import { CippService } from '../src/services/cipp.service.js';
import { Logger } from '../src/utils/logger.js';
import { jsonResponse, queryOf, bodyOf } from './helpers.js';

const logger = new Logger('error');

describe('CippService Intune methods', () => {
  let svc: CippService;
  let fetchMock: jest.Mock<Promise<Response>, [string, RequestInit]>;

  beforeEach(() => {
    svc = new CippService(
      { cipp: { baseUrl: 'https://cipp.example', apiKey: 'test-key' } },
      logger
    );
    fetchMock = jest.fn<Promise<Response>, [string, RequestInit]>(() =>
      Promise.resolve(jsonResponse([]))
    );
    global.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('listIntunePolicy', () => {
    it('sends tenantFilter with no UseReportDB when not requested', async () => {
      await svc.listIntunePolicy('contoso.com');

      const query = queryOf(fetchMock, '/api/ListIntunePolicy');
      expect(query.get('tenantFilter')).toBe('contoso.com');
      expect(query.get('UseReportDB')).toBeNull();
    });

    it('sends UseReportDB=true when requested', async () => {
      await svc.listIntunePolicy('contoso.com', { useReportDB: true });

      const query = queryOf(fetchMock, '/api/ListIntunePolicy');
      expect(query.get('tenantFilter')).toBe('contoso.com');
      expect(query.get('UseReportDB')).toBe('true');
    });

    it('supports allTenants', async () => {
      await svc.listIntunePolicy('allTenants');

      expect(queryOf(fetchMock, '/api/ListIntunePolicy').get('tenantFilter')).toBe('allTenants');
    });
  });

  describe('listIntuneCompliancePolicies', () => {
    it('sends tenantFilter with no UseReportDB when not requested', async () => {
      await svc.listIntuneCompliancePolicies('contoso.com');

      const query = queryOf(fetchMock, '/api/ListCompliancePolicies');
      expect(query.get('tenantFilter')).toBe('contoso.com');
      expect(query.get('UseReportDB')).toBeNull();
    });

    it('sends UseReportDB=true when requested', async () => {
      await svc.listIntuneCompliancePolicies('contoso.com', { useReportDB: true });

      expect(queryOf(fetchMock, '/api/ListCompliancePolicies').get('UseReportDB')).toBe('true');
    });
  });

  describe('compareIntunePolicies', () => {
    it('sends both sides as tenantPolicy sources sharing one tenantFilter', async () => {
      await svc.compareIntunePolicies(
        'contoso.com',
        'policy-a-id',
        'ConfigurationPolicies',
        'policy-b-id',
        'ConfigurationPolicies'
      );

      const body = bodyOf(fetchMock, '/api/ExecCompareIntunePolicy');
      expect(body).toEqual({
        sourceA: {
          type: 'tenantPolicy',
          tenantFilter: 'contoso.com',
          policyId: 'policy-a-id',
          urlName: 'ConfigurationPolicies',
        },
        sourceB: {
          type: 'tenantPolicy',
          tenantFilter: 'contoso.com',
          policyId: 'policy-b-id',
          urlName: 'ConfigurationPolicies',
        },
      });
    });

    it('accepts every documented urlName value', async () => {
      const urlNames = [
        'DeviceConfigurations',
        'ConfigurationPolicies',
        'GroupPolicyConfigurations',
        'deviceCompliancePolicies',
        'WindowsDriverUpdateProfiles',
        'WindowsFeatureUpdateProfiles',
        'windowsQualityUpdatePolicies',
        'windowsQualityUpdateProfiles',
        'hardwareConfigurations',
        'Intents',
        'ManagedAppPolicies',
      ];

      for (const urlName of urlNames) {
        await expect(
          svc.compareIntunePolicies('contoso.com', 'a-id', urlName, 'b-id', urlName)
        ).resolves.toBeDefined();
      }
    });

    it('rejects an unknown policyAUrlName without calling the API', async () => {
      await expect(
        svc.compareIntunePolicies('contoso.com', 'a-id', 'NotARealUrlName', 'b-id', 'Intents')
      ).rejects.toBeInstanceOf(McpError);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('rejects an unknown policyBUrlName without calling the API', async () => {
      await expect(
        svc.compareIntunePolicies('contoso.com', 'a-id', 'Intents', 'b-id', 'NotARealUrlName')
      ).rejects.toBeInstanceOf(McpError);
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });
});
