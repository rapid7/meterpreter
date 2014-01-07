/*!
 * @file adsi_interface.cpp
 * @brief Definitions for functions that directly interact with ADSI
 *        through the (awful) COM interface.
 */
extern "C" {
#include "extapi.h"
#include <Iads.h>
#include <Adshlp.h>
#include <AdsErr.h>
#include "adsi_interface.h"
}

#pragma comment(lib, "Activeds.lib")

#define VALUE_SIZE 512
#define PATH_SIZE 256

/*! @brief The GUID of the Directory Search COM object. */
static const IID IID_IDirectorySearch = { 0x109BA8EC, 0x92F0, 0x11D0, { 0xA7, 0x90, 0x00, 0xC0, 0x4F, 0xD8, 0xD5, 0xA8 } };

/*!
 * @brief Perform a domain query via ADSI.
 * @param lpwDomain Name of the domain that is to be queried.
 * @param lpwFilter The filter to use when reading objects (LDAP style).
 * @param lpwQueryCols Array of column names representing fields to extract.
 * @param queryColCount Number of columns in \c lpwQueryCols.
 * @param maxResults The maximum number of results to return.
 * @param pageSize The size of the page of results to return.
 * @param response The response \c Packet to add the results to.
 */
DWORD domain_query(LPCWSTR lpwDomain, LPWSTR lpwFilter, LPWSTR* lpwQueryCols,
	UINT queryColCount, DWORD maxResults, DWORD pageSize, Packet* response)
{
	HRESULT hResult;
	WCHAR cbPath[PATH_SIZE];

	swprintf_s(cbPath, PATH_SIZE - 1, L"LDAP://%s", lpwDomain);

	if ((hResult = CoInitialize(NULL)) == S_OK)
	{
		IDirectorySearch* pDirSearch = NULL;
		ADS_SEARCH_HANDLE hSearch = NULL;

		do
		{
			// start by trying to create the search object which we can use to run searches
			hResult = ADsOpenObject(cbPath, NULL, NULL, ADS_SECURE_AUTHENTICATION | ADS_READONLY_SERVER, IID_IDirectorySearch, (void**)&pDirSearch);
			if (hResult != S_OK)
			{
				dprintf("[ADSI] Unable to open domain: %x", hResult);
				break;
			}

			// set the limit of results so that we don't take forever on large domains
			ADS_SEARCHPREF_INFO prefInfo[4];
			prefInfo[0].dwSearchPref = ADS_SEARCHPREF_SIZE_LIMIT;
			prefInfo[0].vValue.dwType = ADSTYPE_INTEGER;
			prefInfo[0].vValue.Integer = (ADS_INTEGER)maxResults;
			prefInfo[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
			prefInfo[1].vValue.dwType = ADSTYPE_INTEGER;
			prefInfo[1].vValue.Integer = (ADS_INTEGER)pageSize;
			prefInfo[2].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
			prefInfo[2].vValue.dwType = ADSTYPE_INTEGER;
			prefInfo[2].vValue.Integer = ADS_SCOPE_SUBTREE;
			prefInfo[3].dwSearchPref = ADS_SEARCHPREF_CACHE_RESULTS;
			prefInfo[3].vValue.dwType = ADSTYPE_BOOLEAN;
			prefInfo[3].vValue.Boolean = false;

			dprintf("[ADSI] Setting Max results to %u", (ADS_INTEGER)maxResults);
			dprintf("[ADSI] Setting Page size to %u", (ADS_INTEGER)pageSize);
			if (FAILED(hResult = pDirSearch->SetSearchPreference(prefInfo, 4)))
			{
				dprintf("[ADSI] Failed to set search settings %u %x", pageSize, hResult);
			}

			dprintf("[ADSI] Search executing");
			hResult = pDirSearch->ExecuteSearch(lpwFilter, lpwQueryCols, queryColCount, &hSearch);
			if (hResult != S_OK)
			{
				dprintf("[ADSI] Unable to execute the search");
				break;
			}

			// These buffers are used to store the values that we're reading out of AD
			Tlv* entries = (Tlv*)malloc(queryColCount * sizeof(Tlv));
			char* values = (char*)malloc(queryColCount * VALUE_SIZE);

			DWORD rowsProcessed = 0;

			// now we iterate through the search results
			while (SUCCEEDED((hResult = pDirSearch->GetNextRow(hSearch))) && (maxResults == 0 || rowsProcessed < maxResults))
			{
				if (hResult == S_ADS_NOMORE_ROWS)
				{
					hResult = S_OK;

					// out of results, so bomb out of the loop
					break;
				}

				DWORD dwIndex = 0;
				size_t charsConverted;
				ADS_SEARCH_COLUMN col;

				// iterate through the columns, adding Tlv entries as we go, but only
				// if we can get the values out.
				for (DWORD colIndex = 0; colIndex < queryColCount; ++colIndex)
				{
					char* valueTarget = values + dwIndex * VALUE_SIZE;

					entries[dwIndex].buffer = (PUCHAR)valueTarget;
					entries[dwIndex].header.type = TLV_TYPE_EXT_ADSI_VALUE;

					// try to do something sane based on the type that's being used to store
					// the value.
					HRESULT hr = pDirSearch->GetColumn(hSearch, lpwQueryCols[dwIndex], &col);
					if (SUCCEEDED(hr))
					{
						switch (col.dwADsType)
						{
						case ADSTYPE_LARGE_INTEGER:
							_i64toa_s(col.pADsValues->LargeInteger.QuadPart, valueTarget, VALUE_SIZE, 10);
							entries[dwIndex].header.length = lstrlenA(valueTarget) + 1;
							dprintf("[ADSI] Adding large int value %ul", (UINT)col.pADsValues->Integer);
							break;
						case ADSTYPE_INTEGER:
							_itoa_s((UINT)col.pADsValues->Integer, valueTarget, VALUE_SIZE, 10);
							entries[dwIndex].header.length = lstrlenA(valueTarget) + 1;
							dprintf("[ADSI] Adding int value %u", (UINT)col.pADsValues->Integer);
							break;
						default:
							WCHAR* source = col.dwADsType == ADSTYPE_CASE_IGNORE_STRING
								? col.pADsValues->CaseIgnoreString
								: col.pADsValues->CaseExactString;

							wcstombs_s(&charsConverted, valueTarget, VALUE_SIZE, source, VALUE_SIZE - 1);
							dprintf("[ADSI] Adding string %s", valueTarget);
							entries[dwIndex].header.length = lstrlenA(valueTarget) + 1;
							break;
						}

						pDirSearch->FreeColumn(&col);
					}
					else
					{
						dprintf("[ADSI] Col read failed: %x", hr);
						valueTarget[0] = 0;
						entries[dwIndex].header.length = 1;
					}

					dwIndex++;
				}

				if (dwIndex > 0)
				{
					dprintf("[ADSI] Adding group packet of %u values", dwIndex);
					// Throw the user details together in a group, ready to return.
					packet_add_tlv_group(response, TLV_TYPE_EXT_ADSI_RESULT, entries, dwIndex);
					dprintf("[ADSI] Added group packet of %u values", dwIndex);
				}
				else
				{
					dprintf("[ADSI] Item found, but no fields extracted.");
				}

				++rowsProcessed;
			}

			dprintf("[ADSI] Processed %u. Final result: %u (0x%x)", rowsProcessed, hResult, hResult);

			if (SUCCEEDED(hResult))
			{
				hResult = S_OK;
			}

			free(entries);
			free(values);
		} while (0);

		if (hSearch != NULL)
		{
			pDirSearch->CloseSearchHandle(hSearch);
		}

		if (pDirSearch != NULL)
		{
			pDirSearch->Release();
		}

		CoUninitialize();
	}
	else
	{
		dprintf("[ADSI] Failed to initialize COM");
	}

	return (DWORD)hResult;
}
