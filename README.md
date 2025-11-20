# Dart Test Quality MCP Server

AI'ın Flutter/Dart test kodları yazarken basit ve yetersiz testler yerine **kapsamlı, güçlü ve best practice'lere uygun** testler yazmasını sağlayan MCP (Model Context Protocol) server'ı.

## Sorun

Araştırmalar, AI tarafından üretilen test kodlarının gerçek senaryolarda yalnızca **%47,1 başarı oranına** sahip olduğunu gösteriyor. Yaygın sorunlar:

- Try-catch blokları (test framework'ü bozar)
- Zayıf assertion'lar (isNotNull, any())
- Edge case eksikliği
- Generic test isimleri
- Happy path'e aşırı odaklanma

## Çözüm

Bu MCP server, AI'a test yazarken rehberlik eden 7 tool, 3 resource ve 2 prompt sağlar.

## Kurulum

### 1. Bağımlılıkları yükleyin

```bash
cd dart_test_mcp
npm install
```

### 2. Build edin

```bash
npm run build
```

### 3. Claude Desktop'a ekleyin

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) veya
`%APPDATA%\Claude\claude_desktop_config.json` (Windows) dosyasına ekleyin:

```json
{
  "mcpServers": {
    "dart-test-quality": {
      "command": "node",
      "args": ["/path/to/dart_test_mcp/dist/index.js"]
    }
  }
}
```

## Tools

### 1. `validate_test_code`
Test kodunu anti-pattern'ler için analiz eder.

```
Tespit edilen sorunlar:
- Try-catch blokları
- Zayıf assertion'lar (isNotNull, isNotEmpty)
- any() matcher aşırı kullanımı
- Generic test isimleri
- Logic içeren testler (if/for/while)
- Eksik await
```

### 2. `get_comprehensive_test_guidelines`
Senaryo bazlı test yazım kılavuzu döndürür.

Senaryolar:
- `unit` - Unit test kuralları
- `widget` - Widget test kuralları
- `integration` - Integration test kuralları
- `bloc` - Bloc test kuralları
- `async` - Async test kuralları
- `error_handling` - Exception test kuralları
- `mocking` - Mock kullanım kuralları

### 3. `suggest_edge_cases`
Belirli bir özellik için test edilmesi gereken edge case'leri önerir.

Kategoriler:
- Null/Empty değerler
- Boundary değerler
- Format/Input validasyonu
- Async/Network hataları
- State durumları
- Concurrent access

### 4. `get_test_template`
Test şablonları döndürür.

Şablonlar:
- `unit` - Temel unit test
- `widgetBasic` - Basit widget test
- `widgetInteraction` - Kullanıcı etkileşimli widget test
- `asyncOperation` - Async operasyon testi
- `errorHandling` - Exception testi
- `stream` - Stream testi
- `bloc` - Bloc testi
- `mock` - Mock kullanım örneği
- `goldenTest` - Golden file testi

### 5. `review_assertions`
Assertion'ları inceler ve güçlendirme önerileri sunar.

### 6. `get_test_checklist`
Test kalite kontrol listesi döndürür.

Kontrol kategorileri:
- Structure (AAA pattern, tek sorumluluk)
- Assertions (güçlü doğrulama)
- Coverage (edge case'ler)
- Isolation (bağımsızlık)
- Antipatterns (kaçınılması gerekenler)

### 7. `get_strong_assertion_examples`
Zayıf ve güçlü assertion karşılaştırma örnekleri.

Kategoriler:
- `object` - Obje kontrolü
- `verification` - Mock doğrulama
- `exception` - Exception kontrolü
- `collection` - Koleksiyon kontrolü
- `async` - Async kontrolü

## Resources

### `test-guide://best-practices`
Kapsamlı test yazım best practices özeti.

### `test-guide://matchers`
Tüm Flutter test matcher'larının referans listesi.

### `test-guide://ai-mistakes`
AI'ın yaptığı yaygın hatalar ve çözümleri.

## Prompts

### `comprehensive_test_review`
Test kodunu kapsamlı şekilde inceleyip iyileştirme önerileri sunar.

### `generate_test_suite`
Verilen kod için kapsamlı test suite oluşturur.

## Kullanım Örnekleri

### Test Kodu Validasyonu

```
Tool: validate_test_code
Input: {
  "code": "test('test1', () { try { ... } catch (e) { fail(e); } })"
}
```

Çıktı:
```
🔴 CRITICAL: Test kodunda try-catch bloğu tespit edildi...
🟡 WARNING: Generic test ismi...
```

### Edge Case Önerileri

```
Tool: suggest_edge_cases
Input: {
  "feature_name": "validateEmail",
  "input_types": ["String"],
  "has_async": false,
  "has_network": false
}
```

### Test Şablonu Alma

```
Tool: get_test_template
Input: {
  "template_type": "errorHandling"
}
```

## Temel Kurallar

Bu MCP server aşağıdaki kuralları zorlar:

1. **ASLA try-catch kullanmayın** - Test framework exception'ları handle eder
2. **Güçlü assertion'lar kullanın** - isNotNull yerine spesifik değerler
3. **Edge case'leri test edin** - null, empty, boundary, error
4. **AAA pattern takip edin** - Arrange → Act → Assert
5. **Açıklayıcı test isimleri** - Ne test edildiği anlaşılmalı
6. **Logic kullanmayın** - Testlerde if/for/while olmamalı
7. **Mock'ları doğru kullanın** - Sadece I/O operations

## Katkıda Bulunma

Pull request'ler kabul edilir. Büyük değişiklikler için önce issue açın.

## Lisans

MIT
