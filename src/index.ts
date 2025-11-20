#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// Anti-patterns that AI commonly produces
const ANTI_PATTERNS = {
  tryCatch: {
    pattern: /try\s*\{[\s\S]*?\}\s*catch/g,
    severity: "critical",
    message: "CRITICAL: Test kodunda try-catch bloğu tespit edildi. Test framework'ü exception'ları otomatik olarak ele alır. Try-catch kullanımı gerçek hataları gizler ve yanıltıcı mesajlar üretir.",
    fix: "Try-catch bloğunu tamamen kaldırın. Exception bekliyorsanız expect(() => ..., throwsA(...)) kullanın."
  },
  weakAssertionNotNull: {
    pattern: /expect\([^,]+,\s*isNotNull\s*\)/g,
    severity: "warning",
    message: "Zayıf assertion: isNotNull yetersiz bir doğrulama. Spesifik değerleri kontrol edin.",
    fix: "expect(result, isNotNull) yerine expect(result.specificField, equals(expectedValue)) kullanın."
  },
  weakAssertionNotEmpty: {
    pattern: /expect\([^,]+,\s*isNotEmpty\s*\)/g,
    severity: "warning",
    message: "Zayıf assertion: isNotEmpty yetersiz. Koleksiyonun içeriğini ve uzunluğunu kontrol edin.",
    fix: "expect(list, isNotEmpty) yerine expect(list.length, equals(3)) ve expect(list, contains(expectedItem)) kullanın."
  },
  anyMatcher: {
    pattern: /verify\([^)]*any\(\)[^)]*\)/g,
    severity: "warning",
    message: "any() matcher aşırı kullanımı. Gerçek argümanları doğrulamıyor.",
    fix: "any() yerine argThat(isA<Type>().having((e) => e.field, 'field', expectedValue)) kullanın."
  },
  genericTestName: {
    pattern: /test\s*\(\s*['"`](test\d*|it works|should work|happy path|test\w+)['"`]/gi,
    severity: "warning",
    message: "Generic test ismi. Test ne yaptığını açıkça belirtmeli.",
    fix: "test('methodName returns expectedResult when condition') formatını kullanın."
  },
  logicInTest: {
    pattern: /test\s*\([^)]+\)\s*\{[^}]*\b(if|for|while|switch)\b/g,
    severity: "warning",
    message: "Test kodunda kontrol akış yapısı (if/for/while/switch). Testler basit ve lineer olmalı.",
    fix: "Her senaryo için ayrı test yazın. Loop yerine parametrized test veya ayrı test case'ler kullanın."
  },
  missingAwait: {
    pattern: /(?<!await\s)tester\.(pump|pumpWidget|tap|enterText|drag)/g,
    severity: "critical",
    message: "Widget test'te await eksik. Bu flaky test'lere neden olur.",
    fix: "Tüm tester metodlarının önüne await ekleyin."
  },
  sharedState: {
    pattern: /^(var|let)\s+\w+\s*=(?!\s*null)/gm,
    severity: "info",
    message: "Test dışında değişken tanımı. Shared state test bağımsızlığını bozabilir.",
    fix: "Değişkenleri her test'in içinde veya setUp'ta tanımlayın."
  }
};

// Edge case categories
const EDGE_CASE_CATEGORIES = {
  nullEmpty: [
    "null değer geçildiğinde",
    "boş string geçildiğinde",
    "boş liste geçildiğinde",
    "whitespace-only string geçildiğinde"
  ],
  boundary: [
    "minimum geçerli değer (boundary)",
    "maksimum geçerli değer (boundary)",
    "boundary'nin hemen altı (invalid)",
    "boundary'nin hemen üstü (invalid)",
    "sıfır değeri",
    "negatif değer"
  ],
  format: [
    "geçersiz format",
    "özel karakterler içeren input",
    "unicode karakterler",
    "SQL injection denemesi",
    "XSS denemesi",
    "çok uzun input",
    "emoji içeren input"
  ],
  async: [
    "network timeout",
    "network hatası",
    "boş response",
    "malformed response",
    "rate limiting",
    "authentication hatası"
  ],
  concurrent: [
    "eşzamanlı erişim",
    "race condition senaryosu",
    "deadlock potansiyeli"
  ],
  state: [
    "initial state",
    "loading state",
    "error state",
    "success state",
    "empty state",
    "partial data state"
  ]
};

// Test templates
const TEST_TEMPLATES = {
  unit: `test('methodName returns expectedResult when condition', () {
  // Arrange - Test verisini hazırla
  final sut = SystemUnderTest();
  final input = TestInput(value: 'test');

  // Act - Tek bir aksiyon
  final result = sut.methodName(input);

  // Assert - Spesifik değerleri doğrula
  expect(result.field, equals('expectedValue'));
  expect(result.count, equals(42));
});`,

  widgetBasic: `testWidgets('widget displays correct content when condition', (tester) async {
  // Arrange
  final testData = TestData(title: 'Test', value: 42);

  // Act
  await tester.pumpWidget(
    MaterialApp(
      home: MyWidget(data: testData),
    ),
  );
  await tester.pumpAndSettle();

  // Assert
  expect(find.text('Test'), findsOneWidget);
  expect(find.text('42'), findsOneWidget);
});`,

  widgetInteraction: `testWidgets('widget responds to user interaction correctly', (tester) async {
  // Arrange
  final mockService = MockService();
  when(() => mockService.doAction(any())).thenAnswer((_) async => Result.success());

  await tester.pumpWidget(
    MaterialApp(
      home: MyWidget(service: mockService),
    ),
  );

  // Act
  await tester.enterText(find.byKey(Key('input_field')), 'test value');
  await tester.tap(find.byKey(Key('submit_button')));
  await tester.pumpAndSettle();

  // Assert
  verify(() => mockService.doAction('test value')).called(1);
  expect(find.text('Success'), findsOneWidget);
});`,

  asyncOperation: `test('async operation completes with expected result', () async {
  // Arrange
  final mockApi = MockApi();
  final service = MyService(mockApi);

  when(() => mockApi.fetchData(any()))
      .thenAnswer((_) async => TestData(id: '1', value: 'test'));

  // Act
  final result = await service.getData('123');

  // Assert
  expect(result.id, equals('1'));
  expect(result.value, equals('test'));
  verify(() => mockApi.fetchData('123')).called(1);
});`,

  errorHandling: `test('throws specific exception when error condition', () {
  // Arrange
  final sut = SystemUnderTest();

  // Act & Assert
  expect(
    () => sut.methodWithValidation(invalidInput),
    throwsA(
      isA<ValidationException>()
          .having((e) => e.message, 'message', contains('expected error text'))
          .having((e) => e.code, 'code', equals('INVALID_INPUT'))
    ),
  );
});`,

  stream: `test('stream emits expected values in order', () async {
  // Arrange
  final controller = StreamController<int>();
  final service = MyService(controller.stream);

  // Act
  final future = expectLater(
    service.outputStream,
    emitsInOrder([
      equals(1),
      equals(2),
      equals(3),
      emitsDone,
    ]),
  );

  controller.add(1);
  controller.add(2);
  controller.add(3);
  await controller.close();

  // Assert
  await future;
});`,

  bloc: `blocTest<MyBloc, MyState>(
  'emits [loading, success] when action succeeds',
  build: () {
    when(() => mockRepository.getData())
        .thenAnswer((_) async => testData);
    return MyBloc(repository: mockRepository);
  },
  act: (bloc) => bloc.add(LoadDataRequested()),
  expect: () => [
    MyState.loading(),
    MyState.success(testData),
  ],
  verify: (_) {
    verify(() => mockRepository.getData()).called(1);
  },
);`,

  mock: `// Mock oluşturma
class MockApiService extends Mock implements ApiService {}

// Test'te kullanım
test('service calls API with correct parameters', () async {
  // Arrange
  final mockApi = MockApiService();
  final service = MyService(mockApi);

  when(() => mockApi.fetch(any()))
      .thenAnswer((_) async => TestData());

  // Act
  await service.loadData('123');

  // Assert - Spesifik argümanları doğrula
  verify(() => mockApi.fetch(argThat(
    isA<Request>()
        .having((r) => r.id, 'id', equals('123'))
        .having((r) => r.includeDetails, 'includeDetails', isTrue)
  ))).called(1);
});`,

  goldenTest: `testWidgets('widget matches golden file', (tester) async {
  await tester.pumpWidget(
    MaterialApp(
      theme: ThemeData.light(),
      home: Scaffold(
        body: MyComplexWidget(
          title: 'Golden Test',
          items: ['Item 1', 'Item 2', 'Item 3'],
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();

  await expectLater(
    find.byType(MyComplexWidget),
    matchesGoldenFile('goldens/my_complex_widget.png'),
  );
});`
};

// Comprehensive test checklist
const TEST_CHECKLIST = {
  structure: [
    "AAA (Arrange-Act-Assert) pattern kullanılmış mı?",
    "Her test tek bir şeyi mi test ediyor?",
    "Test ismi ne test edildiğini açıkça belirtiyor mu?",
    "setUp ve tearDown uygun şekilde kullanılmış mı?",
    "Testler group() ile organize edilmiş mi?"
  ],
  assertions: [
    "Spesifik değerler doğrulanıyor mu (isNotNull yerine)?",
    "Birden fazla ilgili assertion var mı?",
    "Error mesajları ve kodları doğrulanıyor mu?",
    "any() yerine spesifik matcher'lar kullanılmış mı?",
    "having() ile detaylı property kontrolü yapılmış mı?"
  ],
  coverage: [
    "Happy path test edilmiş mi?",
    "Null/empty değerler test edilmiş mi?",
    "Boundary değerler test edilmiş mi?",
    "Error/exception durumları test edilmiş mi?",
    "Edge case'ler kapsanmış mı?"
  ],
  isolation: [
    "External dependencies mock'lanmış mı?",
    "Her test bağımsız çalışabilir mi?",
    "Shared state kullanılmamış mı?",
    "Network/file system/database mock'lanmış mı?"
  ],
  antipatterns: [
    "Try-catch blokları kullanılmamış mı?",
    "Test'te logic (if/for/while) yok mu?",
    "Generic test isimleri kullanılmamış mı?",
    "Over-mocking yapılmamış mı?",
    "await unutulmamış mı?"
  ]
};

// Strong assertion examples
const STRONG_ASSERTION_EXAMPLES = {
  object: `// Zayıf
expect(result, isNotNull);

// Güçlü
expect(result.id, equals('expected-id'));
expect(result.name, equals('Test User'));
expect(result.createdAt, isA<DateTime>());
expect(result.tags, containsAll(['tag1', 'tag2']));`,

  verification: `// Zayıf
verify(mockRepo.save(any)).called(1);

// Güçlü
verify(() => mockRepo.save(argThat(
  isA<User>()
      .having((u) => u.name, 'name', equals('John'))
      .having((u) => u.email, 'email', equals('john@test.com'))
      .having((u) => u.age, 'age', greaterThan(18))
))).called(1);`,

  exception: `// Zayıf
expect(() => sut.validate(input), throwsException);

// Güçlü
expect(
  () => sut.validate(input),
  throwsA(
    isA<ValidationException>()
        .having((e) => e.message, 'message', contains('invalid email'))
        .having((e) => e.field, 'field', equals('email'))
        .having((e) => e.code, 'code', equals('INVALID_FORMAT'))
  ),
);`,

  collection: `// Zayıf
expect(list, isNotEmpty);

// Güçlü
expect(list.length, equals(3));
expect(list.first.id, equals('1'));
expect(list, everyElement(isA<Item>().having((i) => i.isValid, 'isValid', isTrue)));
expect(list.map((e) => e.name), containsAll(['A', 'B', 'C']));`,

  async: `// Zayıf
await expectLater(future, completes);

// Güçlü
await expectLater(
  future,
  completion(
    isA<Result>()
        .having((r) => r.success, 'success', isTrue)
        .having((r) => r.data.length, 'data.length', equals(5))
  ),
);`
};

// Create server
const server = new Server(
  {
    name: "dart-test-quality-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
      resources: {},
      prompts: {},
    },
  }
);

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "validate_test_code",
        description: "Test kodunu anti-pattern'ler ve best practice ihlalleri için analiz eder. AI'ın yaygın hatalarını tespit eder.",
        inputSchema: {
          type: "object",
          properties: {
            code: {
              type: "string",
              description: "Analiz edilecek test kodu"
            }
          },
          required: ["code"]
        }
      },
      {
        name: "get_comprehensive_test_guidelines",
        description: "Belirli bir senaryo için kapsamlı test yazma kılavuzu döndürür.",
        inputSchema: {
          type: "object",
          properties: {
            scenario: {
              type: "string",
              enum: ["unit", "widget", "integration", "bloc", "async", "error_handling", "mocking"],
              description: "Test senaryosu türü"
            },
            feature_description: {
              type: "string",
              description: "Test edilecek özelliğin kısa açıklaması"
            }
          },
          required: ["scenario"]
        }
      },
      {
        name: "suggest_edge_cases",
        description: "Belirli bir fonksiyon/özellik için test edilmesi gereken edge case'leri önerir.",
        inputSchema: {
          type: "object",
          properties: {
            feature_name: {
              type: "string",
              description: "Özellik veya fonksiyon adı"
            },
            input_types: {
              type: "array",
              items: { type: "string" },
              description: "Input türleri (string, int, List, etc.)"
            },
            has_async: {
              type: "boolean",
              description: "Async operasyon içeriyor mu?"
            },
            has_network: {
              type: "boolean",
              description: "Network çağrısı yapıyor mu?"
            }
          },
          required: ["feature_name"]
        }
      },
      {
        name: "get_test_template",
        description: "Belirli test türü için şablon kod döndürür.",
        inputSchema: {
          type: "object",
          properties: {
            template_type: {
              type: "string",
              enum: ["unit", "widgetBasic", "widgetInteraction", "asyncOperation", "errorHandling", "stream", "bloc", "mock", "goldenTest"],
              description: "Şablon türü"
            }
          },
          required: ["template_type"]
        }
      },
      {
        name: "review_assertions",
        description: "Test assertion'larını inceler ve güçlendirme önerileri sunar.",
        inputSchema: {
          type: "object",
          properties: {
            assertions: {
              type: "string",
              description: "İncelenecek assertion kodu"
            }
          },
          required: ["assertions"]
        }
      },
      {
        name: "get_test_checklist",
        description: "Test kalitesi için kontrol listesi döndürür.",
        inputSchema: {
          type: "object",
          properties: {
            test_type: {
              type: "string",
              enum: ["unit", "widget", "integration", "all"],
              description: "Test türü"
            }
          },
          required: ["test_type"]
        }
      },
      {
        name: "get_strong_assertion_examples",
        description: "Zayıf ve güçlü assertion karşılaştırma örnekleri döndürür.",
        inputSchema: {
          type: "object",
          properties: {
            category: {
              type: "string",
              enum: ["object", "verification", "exception", "collection", "async", "all"],
              description: "Assertion kategorisi"
            }
          },
          required: ["category"]
        }
      }
    ]
  };
});

// Call tool handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "validate_test_code": {
      const code = args?.code as string;
      const issues: Array<{severity: string; message: string; fix: string; location?: string}> = [];

      for (const [key, pattern] of Object.entries(ANTI_PATTERNS)) {
        const matches = code.match(pattern.pattern);
        if (matches) {
          issues.push({
            severity: pattern.severity,
            message: pattern.message,
            fix: pattern.fix,
            location: matches[0].substring(0, 50) + (matches[0].length > 50 ? '...' : '')
          });
        }
      }

      // Additional checks
      if (!code.includes('expect(')) {
        issues.push({
          severity: 'critical',
          message: 'Test\'te hiç assertion yok! Her test en az bir expect() içermeli.',
          fix: 'Test edilen davranışı doğrulayan expect() statement\'ları ekleyin.'
        });
      }

      if (code.includes('expect(') && (code.match(/expect\(/g)?.length || 0) < 2) {
        issues.push({
          severity: 'info',
          message: 'Tek assertion bulundu. Kapsamlı testler genellikle birden fazla assertion içerir.',
          fix: 'İlgili tüm değerleri ayrı expect() statement\'ları ile doğrulayın.'
        });
      }

      const hasArrangeComment = code.includes('// Arrange') || code.includes('// ARRANGE');
      const hasActComment = code.includes('// Act') || code.includes('// ACT');
      const hasAssertComment = code.includes('// Assert') || code.includes('// ASSERT');

      if (!hasArrangeComment && !hasActComment && !hasAssertComment) {
        issues.push({
          severity: 'info',
          message: 'AAA pattern yorum satırları eksik. Okunabilirlik için önerilir.',
          fix: '// Arrange, // Act, // Assert yorumlarını ekleyin.'
        });
      }

      const summary = {
        critical: issues.filter(i => i.severity === 'critical').length,
        warning: issues.filter(i => i.severity === 'warning').length,
        info: issues.filter(i => i.severity === 'info').length
      };

      let resultText = `## Test Kod Analizi Sonucu\n\n`;
      resultText += `**Özet:** ${summary.critical} kritik, ${summary.warning} uyarı, ${summary.info} bilgi\n\n`;

      if (issues.length === 0) {
        resultText += `✅ Temel anti-pattern tespit edilmedi. Ancak edge case coverage ve assertion gücünü manuel olarak kontrol edin.\n`;
      } else {
        resultText += `### Tespit Edilen Sorunlar\n\n`;
        for (const issue of issues) {
          const icon = issue.severity === 'critical' ? '🔴' : issue.severity === 'warning' ? '🟡' : '🔵';
          resultText += `${icon} **${issue.severity.toUpperCase()}**\n`;
          resultText += `${issue.message}\n`;
          resultText += `**Düzeltme:** ${issue.fix}\n`;
          if (issue.location) {
            resultText += `**Konum:** \`${issue.location}\`\n`;
          }
          resultText += `\n`;
        }
      }

      return {
        content: [{ type: "text", text: resultText }]
      };
    }

    case "get_comprehensive_test_guidelines": {
      const scenario = args?.scenario as string;
      const featureDesc = args?.feature_description as string || '';

      let guidelines = `## ${scenario.toUpperCase()} Test Yazım Kılavuzu\n\n`;

      if (featureDesc) {
        guidelines += `**Test edilecek özellik:** ${featureDesc}\n\n`;
      }

      guidelines += `### Temel Kurallar\n\n`;
      guidelines += `1. **AAA Pattern kullanın:** Arrange → Act → Assert\n`;
      guidelines += `2. **Tek sorumluluk:** Her test tek bir davranışı test etmeli\n`;
      guidelines += `3. **Açıklayıcı isim:** Test ismi scenario ve beklenen sonucu belirtmeli\n`;
      guidelines += `4. **Güçlü assertion:** isNotNull/isNotEmpty yerine spesifik değerler\n`;
      guidelines += `5. **Try-catch YASAK:** Exception test ediyorsanız throwsA() kullanın\n\n`;

      switch (scenario) {
        case 'unit':
          guidelines += `### Unit Test Özel Kuralları\n\n`;
          guidelines += `- External dependency'leri mock'layın\n`;
          guidelines += `- Pure function'ları gerçek objelerle test edin\n`;
          guidelines += `- Boundary değerleri mutlaka test edin\n`;
          guidelines += `- Her public method için en az 3-5 test yazın\n\n`;
          guidelines += `### Test Edilmesi Gerekenler\n\n`;
          guidelines += `- ✅ Happy path (normal çalışma)\n`;
          guidelines += `- ✅ Null/empty input'lar\n`;
          guidelines += `- ✅ Boundary değerler (min, max, min-1, max+1)\n`;
          guidelines += `- ✅ Invalid input'lar\n`;
          guidelines += `- ✅ Exception/error durumları\n`;
          break;

        case 'widget':
          guidelines += `### Widget Test Özel Kuralları\n\n`;
          guidelines += `- Her async operasyonda await kullanın\n`;
          guidelines += `- pumpAndSettle() ile animasyonların bitmesini bekleyin\n`;
          guidelines += `- Key kullanarak widget'ları bulun (byType yerine)\n`;
          guidelines += `- MaterialApp wrapper kullanın\n\n`;
          guidelines += `### Test Edilmesi Gerekenler\n\n`;
          guidelines += `- ✅ Initial render durumu\n`;
          guidelines += `- ✅ User interaction'lar (tap, scroll, text input)\n`;
          guidelines += `- ✅ State değişimleri\n`;
          guidelines += `- ✅ Loading/error/empty state'ler\n`;
          guidelines += `- ✅ Navigation\n`;
          break;

        case 'bloc':
          guidelines += `### Bloc Test Özel Kuralları\n\n`;
          guidelines += `- blocTest kullanın\n`;
          guidelines += `- Tüm state geçişlerini doğrulayın\n`;
          guidelines += `- Repository/service mock'layın\n`;
          guidelines += `- Error state'leri test edin\n\n`;
          guidelines += `### Test Edilmesi Gerekenler\n\n`;
          guidelines += `- ✅ Her event için state değişimleri\n`;
          guidelines += `- ✅ Loading → Success akışı\n`;
          guidelines += `- ✅ Loading → Error akışı\n`;
          guidelines += `- ✅ Concurrent event handling\n`;
          guidelines += `- ✅ Initial state\n`;
          break;

        case 'async':
          guidelines += `### Async Test Özel Kuralları\n\n`;
          guidelines += `- Test fonksiyonunu async yapın\n`;
          guidelines += `- Tüm Future'ları await edin\n`;
          guidelines += `- expectLater kullanın\n`;
          guidelines += `- Timeout senaryolarını test edin\n\n`;
          guidelines += `### Test Edilmesi Gerekenler\n\n`;
          guidelines += `- ✅ Başarılı completion\n`;
          guidelines += `- ✅ Timeout durumu\n`;
          guidelines += `- ✅ Network hatası\n`;
          guidelines += `- ✅ Concurrent operations\n`;
          guidelines += `- ✅ Cancellation\n`;
          break;

        case 'error_handling':
          guidelines += `### Error Handling Test Özel Kuralları\n\n`;
          guidelines += `- throwsA() matcher kullanın\n`;
          guidelines += `- Exception type, message ve code doğrulayın\n`;
          guidelines += `- having() ile detaylı kontrol yapın\n`;
          guidelines += `- Try-catch KESİNLİKLE kullanmayın\n\n`;
          guidelines += `### Test Edilmesi Gerekenler\n\n`;
          guidelines += `- ✅ Her exception type\n`;
          guidelines += `- ✅ Exception message içeriği\n`;
          guidelines += `- ✅ Exception'daki ek bilgiler (code, field, etc.)\n`;
          guidelines += `- ✅ Nested exception'lar\n`;
          break;

        case 'mocking':
          guidelines += `### Mocking Özel Kuralları\n\n`;
          guidelines += `- Mocktail kullanın (code generation gerektirmez)\n`;
          guidelines += `- Sadece I/O operations'ları mock'layın\n`;
          guidelines += `- Pure function ve hesaplamaları mock'lamayın\n`;
          guidelines += `- argThat ile spesifik argümanları doğrulayın\n\n`;
          guidelines += `### Mock Kullanılması Gerekenler\n\n`;
          guidelines += `- ✅ Network calls\n`;
          guidelines += `- ✅ Database operations\n`;
          guidelines += `- ✅ File system\n`;
          guidelines += `- ✅ Time/date operations\n`;
          guidelines += `- ❌ Pure calculations\n`;
          guidelines += `- ❌ Value objects\n`;
          guidelines += `- ❌ Formatters\n`;
          break;

        case 'integration':
          guidelines += `### Integration Test Özel Kuralları\n\n`;
          guidelines += `- IntegrationTestWidgetsFlutterBinding kullanın\n`;
          guidelines += `- Page Object Pattern uygulayın\n`;
          guidelines += `- Gerçek uygulama akışını test edin\n`;
          guidelines += `- Backend'i mock'layabilirsiniz\n\n`;
          guidelines += `### Test Edilmesi Gerekenler\n\n`;
          guidelines += `- ✅ End-to-end user journey\n`;
          guidelines += `- ✅ Navigation flow\n`;
          guidelines += `- ✅ Data persistence\n`;
          guidelines += `- ✅ Authentication flow\n`;
          break;
      }

      return {
        content: [{ type: "text", text: guidelines }]
      };
    }

    case "suggest_edge_cases": {
      const featureName = args?.feature_name as string;
      const inputTypes = args?.input_types as string[] || [];
      const hasAsync = args?.has_async as boolean || false;
      const hasNetwork = args?.has_network as boolean || false;

      let suggestions = `## ${featureName} için Edge Case Önerileri\n\n`;

      suggestions += `### Zorunlu Test Senaryoları\n\n`;

      // Always include null/empty
      suggestions += `#### Null/Empty Değerler\n`;
      for (const edgeCase of EDGE_CASE_CATEGORIES.nullEmpty) {
        suggestions += `- [ ] ${edgeCase}\n`;
      }
      suggestions += `\n`;

      // Boundary values
      suggestions += `#### Boundary Değerler\n`;
      for (const edgeCase of EDGE_CASE_CATEGORIES.boundary) {
        suggestions += `- [ ] ${edgeCase}\n`;
      }
      suggestions += `\n`;

      // Input type specific
      if (inputTypes.includes('string') || inputTypes.includes('String')) {
        suggestions += `#### String Input Özel Durumlar\n`;
        for (const edgeCase of EDGE_CASE_CATEGORIES.format) {
          suggestions += `- [ ] ${edgeCase}\n`;
        }
        suggestions += `\n`;
      }

      // Async specific
      if (hasAsync || hasNetwork) {
        suggestions += `#### Async/Network Özel Durumlar\n`;
        for (const edgeCase of EDGE_CASE_CATEGORIES.async) {
          suggestions += `- [ ] ${edgeCase}\n`;
        }
        suggestions += `\n`;
      }

      // State testing
      suggestions += `#### State Durumları\n`;
      for (const edgeCase of EDGE_CASE_CATEGORIES.state) {
        suggestions += `- [ ] ${edgeCase}\n`;
      }
      suggestions += `\n`;

      // Concurrent access
      if (hasAsync) {
        suggestions += `#### Eşzamanlılık Durumları\n`;
        for (const edgeCase of EDGE_CASE_CATEGORIES.concurrent) {
          suggestions += `- [ ] ${edgeCase}\n`;
        }
        suggestions += `\n`;
      }

      suggestions += `### Örnek Test Şablonu\n\n`;
      suggestions += `\`\`\`dart\n`;
      suggestions += `group('${featureName} edge cases', () {\n`;
      suggestions += `  test('throws ArgumentError when input is null', () {\n`;
      suggestions += `    expect(\n`;
      suggestions += `      () => ${featureName.toLowerCase()}(null),\n`;
      suggestions += `      throwsA(isA<ArgumentError>()),\n`;
      suggestions += `    );\n`;
      suggestions += `  });\n\n`;
      suggestions += `  test('handles empty string gracefully', () {\n`;
      suggestions += `    final result = ${featureName.toLowerCase()}('');\n`;
      suggestions += `    expect(result.isValid, isFalse);\n`;
      suggestions += `    expect(result.error, contains('empty'));\n`;
      suggestions += `  });\n\n`;
      suggestions += `  test('accepts minimum valid value', () {\n`;
      suggestions += `    final result = ${featureName.toLowerCase()}(minValue);\n`;
      suggestions += `    expect(result.isValid, isTrue);\n`;
      suggestions += `  });\n`;
      suggestions += `});\n`;
      suggestions += `\`\`\`\n`;

      return {
        content: [{ type: "text", text: suggestions }]
      };
    }

    case "get_test_template": {
      const templateType = args?.template_type as string;
      const template = TEST_TEMPLATES[templateType as keyof typeof TEST_TEMPLATES];

      if (!template) {
        return {
          content: [{ type: "text", text: `Template '${templateType}' bulunamadı.` }]
        };
      }

      let result = `## ${templateType} Test Şablonu\n\n`;
      result += `\`\`\`dart\n${template}\n\`\`\`\n\n`;
      result += `### Kullanım Notları\n\n`;
      result += `- Bu şablonu kendi test senaryonuza göre düzenleyin\n`;
      result += `- Tüm placeholder değerleri gerçek değerlerle değiştirin\n`;
      result += `- AAA pattern yorumlarını koruyun\n`;
      result += `- Assertion'ları spesifik değerlerle güçlendirin\n`;

      return {
        content: [{ type: "text", text: result }]
      };
    }

    case "review_assertions": {
      const assertions = args?.assertions as string;
      let review = `## Assertion İncelemesi\n\n`;

      // Check for weak patterns
      const weakPatterns = [
        { pattern: /isNotNull/, suggestion: "Spesifik değer kontrolü ekleyin" },
        { pattern: /isNotEmpty/, suggestion: "Koleksiyon içeriğini ve uzunluğunu kontrol edin" },
        { pattern: /isTrue(?!\)|\w)/, suggestion: "Boolean yerine spesifik state kontrolü yapın" },
        { pattern: /isFalse(?!\)|\w)/, suggestion: "Boolean yerine spesifik error/state kontrolü yapın" },
        { pattern: /any\(\)/, suggestion: "argThat ile spesifik değer kontrolü yapın" },
        { pattern: /completes(?!\()/, suggestion: "completion() ile dönüş değerini kontrol edin" }
      ];

      const found: string[] = [];
      for (const wp of weakPatterns) {
        if (wp.pattern.test(assertions)) {
          found.push(`- **${wp.pattern.toString().slice(1, -1)}** bulundu: ${wp.suggestion}`);
        }
      }

      if (found.length > 0) {
        review += `### Güçlendirme Önerileri\n\n`;
        review += found.join('\n') + '\n\n';
      } else {
        review += `✅ Temel zayıf pattern tespit edilmedi.\n\n`;
      }

      review += `### Güçlü Assertion Örnekleri\n\n`;
      review += `\`\`\`dart\n`;
      review += `// Object kontrolü\n`;
      review += `expect(result.id, equals('expected-id'));\n`;
      review += `expect(result.name, equals('Test'));\n\n`;
      review += `// Collection kontrolü\n`;
      review += `expect(list.length, equals(3));\n`;
      review += `expect(list, contains(expectedItem));\n`;
      review += `expect(list.first.id, equals('1'));\n\n`;
      review += `// Verification\n`;
      review += `verify(() => mock.method(argThat(\n`;
      review += `  isA<Request>()\n`;
      review += `      .having((r) => r.id, 'id', equals('123'))\n`;
      review += `))).called(1);\n`;
      review += `\`\`\`\n`;

      return {
        content: [{ type: "text", text: review }]
      };
    }

    case "get_test_checklist": {
      const testType = args?.test_type as string;

      let checklist = `## Test Kalite Kontrol Listesi\n\n`;

      const categories = testType === 'all'
        ? Object.keys(TEST_CHECKLIST)
        : Object.keys(TEST_CHECKLIST);

      for (const category of categories) {
        const items = TEST_CHECKLIST[category as keyof typeof TEST_CHECKLIST];
        checklist += `### ${category.charAt(0).toUpperCase() + category.slice(1)}\n\n`;
        for (const item of items) {
          checklist += `- [ ] ${item}\n`;
        }
        checklist += `\n`;
      }

      return {
        content: [{ type: "text", text: checklist }]
      };
    }

    case "get_strong_assertion_examples": {
      const category = args?.category as string;

      let examples = `## Güçlü Assertion Örnekleri\n\n`;

      if (category === 'all') {
        for (const [cat, example] of Object.entries(STRONG_ASSERTION_EXAMPLES)) {
          examples += `### ${cat.charAt(0).toUpperCase() + cat.slice(1)}\n\n`;
          examples += `\`\`\`dart\n${example}\n\`\`\`\n\n`;
        }
      } else {
        const example = STRONG_ASSERTION_EXAMPLES[category as keyof typeof STRONG_ASSERTION_EXAMPLES];
        if (example) {
          examples += `### ${category.charAt(0).toUpperCase() + category.slice(1)}\n\n`;
          examples += `\`\`\`dart\n${example}\n\`\`\`\n`;
        } else {
          examples = `Kategori '${category}' bulunamadı.`;
        }
      }

      return {
        content: [{ type: "text", text: examples }]
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Bilinmeyen tool: ${name}` }]
      };
  }
});

// List resources handler
server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
      {
        uri: "test-guide://best-practices",
        name: "Flutter/Dart Test Best Practices",
        description: "Kapsamlı test yazım rehberi ve anti-pattern'ler",
        mimeType: "text/markdown"
      },
      {
        uri: "test-guide://matchers",
        name: "Flutter Test Matchers",
        description: "Tüm matcher'ların referans listesi",
        mimeType: "text/markdown"
      },
      {
        uri: "test-guide://ai-mistakes",
        name: "AI Test Yazım Hataları",
        description: "AI'ın yaptığı yaygın hatalar ve çözümleri",
        mimeType: "text/markdown"
      }
    ]
  };
});

// Read resource handler
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request.params.uri;

  switch (uri) {
    case "test-guide://best-practices":
      return {
        contents: [
          {
            uri,
            mimeType: "text/markdown",
            text: `# Flutter/Dart Test Best Practices Özeti

## Altın Kurallar

1. **AAA Pattern:** Arrange → Act → Assert
2. **Tek sorumluluk:** Her test tek bir şeyi test etsin
3. **Try-catch YASAK:** Test framework exception'ları handle eder
4. **Güçlü assertion:** isNotNull yerine spesifik değerler
5. **Bağımsızlık:** Her test izole çalışmalı

## Test Piramidi

- %70 Unit Tests
- %20 Widget Tests
- %10 Integration Tests

## Assertion Güçlendirme

\`\`\`dart
// ❌ Zayıf
expect(result, isNotNull);

// ✅ Güçlü
expect(result.id, equals('123'));
expect(result.name, equals('Test'));
\`\`\`

## Edge Case Zorunlulukları

Her test suite şunları içermeli:
- Null/empty değer testleri
- Boundary value testleri
- Error/exception testleri
- Invalid input testleri
`
          }
        ]
      };

    case "test-guide://matchers":
      return {
        contents: [
          {
            uri,
            mimeType: "text/markdown",
            text: `# Flutter Test Matcher Referansı

## Temel Matcher'lar

\`\`\`dart
// Eşitlik
equals(value)
same(object)
isA<Type>()

// Boolean
isTrue
isFalse
isNull
isNotNull

// Sayısal
greaterThan(n)
lessThan(n)
closeTo(n, delta)
inInclusiveRange(low, high)
\`\`\`

## Collection Matcher'ları

\`\`\`dart
contains(item)
containsAll([items])
everyElement(matcher)
hasLength(n)
isEmpty
isNotEmpty
\`\`\`

## String Matcher'ları

\`\`\`dart
startsWith(prefix)
endsWith(suffix)
contains(substring)
matches(regexp)
\`\`\`

## Exception Matcher'ları

\`\`\`dart
throwsA(matcher)
throwsArgumentError
throwsException
throwsStateError
\`\`\`

## Widget Matcher'ları

\`\`\`dart
findsOneWidget
findsNothing
findsNWidgets(n)
findsAtLeastNWidgets(n)
\`\`\`

## having() ile Detaylı Kontrol

\`\`\`dart
isA<User>()
    .having((u) => u.name, 'name', equals('John'))
    .having((u) => u.age, 'age', greaterThan(18))
\`\`\`
`
          }
        ]
      };

    case "test-guide://ai-mistakes":
      return {
        contents: [
          {
            uri,
            mimeType: "text/markdown",
            text: `# AI'ın Yaygın Test Yazım Hataları

## 1. Try-Catch Kullanımı (KRİTİK)

❌ **AI Hatası:**
\`\`\`dart
test('test', () {
  try {
    result = method();
    expect(result, isTrue);
  } catch (e) {
    fail('Failed: \$e');
  }
});
\`\`\`

✅ **Doğru:**
\`\`\`dart
test('test', () {
  final result = method();
  expect(result, isTrue);
});
\`\`\`

## 2. Zayıf Assertion'lar

❌ **AI Hatası:**
\`\`\`dart
expect(result, isNotNull);
verify(mock.save(any)).called(1);
\`\`\`

✅ **Doğru:**
\`\`\`dart
expect(result.id, equals('123'));
verify(() => mock.save(argThat(
  isA<User>().having((u) => u.id, 'id', '123')
))).called(1);
\`\`\`

## 3. Generic Test İsimleri

❌ **AI Hatası:**
\`\`\`dart
test('test1', () {});
test('should work', () {});
\`\`\`

✅ **Doğru:**
\`\`\`dart
test('returns user when id is valid', () {});
test('throws ArgumentError when id is empty', () {});
\`\`\`

## 4. Edge Case Eksikliği

AI genellikle sadece happy path test eder.

**Eksik olanlar:**
- Null/empty değerler
- Boundary değerler
- Error durumları
- Network hataları

## 5. Logic İçeren Testler

❌ **AI Hatası:**
\`\`\`dart
test('validates users', () {
  for (final user in users) {
    if (validator.validate(user)) {
      count++;
    }
  }
  expect(count, greaterThan(0));
});
\`\`\`

✅ **Doğru:**
Her senaryo için ayrı test yazın.
`
          }
        ]
      };

    default:
      return {
        contents: [
          {
            uri,
            mimeType: "text/plain",
            text: `Resource '${uri}' bulunamadı.`
          }
        ]
      };
  }
});

// List prompts handler
server.setRequestHandler(ListPromptsRequestSchema, async () => {
  return {
    prompts: [
      {
        name: "comprehensive_test_review",
        description: "Test kodunu kapsamlı şekilde inceler ve iyileştirme önerileri sunar",
        arguments: [
          {
            name: "test_code",
            description: "İncelenecek test kodu",
            required: true
          }
        ]
      },
      {
        name: "generate_test_suite",
        description: "Bir fonksiyon/sınıf için kapsamlı test suite oluşturur",
        arguments: [
          {
            name: "code",
            description: "Test edilecek kod",
            required: true
          },
          {
            name: "type",
            description: "Test türü (unit/widget/integration)",
            required: false
          }
        ]
      }
    ]
  };
});

// Get prompt handler
server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "comprehensive_test_review":
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Aşağıdaki test kodunu kapsamlı şekilde incele ve iyileştir.

Kontrol listesi:
1. Try-catch blokları var mı? (varsa kaldır)
2. Assertion'lar yeterince güçlü mü? (isNotNull yerine spesifik değerler)
3. any() matcher aşırı kullanılmış mı?
4. Test isimleri açıklayıcı mı?
5. AAA pattern takip ediliyor mu?
6. Edge case'ler kapsanmış mı?
7. Logic (if/for/while) var mı testlerde?
8. Mock kullanımı uygun mu?

İncelenecek kod:

\`\`\`dart
${args?.test_code || '// Kod sağlanmadı'}
\`\`\`

Her sorun için:
- Sorunun ne olduğunu açıkla
- Neden sorun olduğunu belirt
- Düzeltilmiş kodu göster`
            }
          }
        ]
      };

    case "generate_test_suite":
      const testType = args?.type || 'unit';
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Aşağıdaki kod için kapsamlı bir ${testType} test suite oluştur.

KESİNLİKLE uyulması gereken kurallar:
1. ASLA try-catch kullanma
2. Her test'te AAA pattern (Arrange-Act-Assert) kullan
3. Güçlü assertion'lar kullan (isNotNull yerine spesifik değerler)
4. any() yerine argThat ile spesifik değer kontrolü yap
5. Test isimlerini açıklayıcı yaz: 'methodName returns X when Y'

ZORUNLU test edilmesi gerekenler:
- Happy path (normal çalışma)
- Null input
- Empty input
- Invalid input
- Boundary değerler (min, max, min-1, max+1)
- Error/exception durumları
- Edge case'ler

Test edilecek kod:

\`\`\`dart
${args?.code || '// Kod sağlanmadı'}
\`\`\`

Her test için:
- Açıklayıcı isim
- AAA pattern yorumları
- Güçlü assertion'lar
- Gerekirse mock'lar`
            }
          }
        ]
      };

    default:
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Bilinmeyen prompt: ${name}`
            }
          }
        ]
      };
  }
});

// Main function
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Dart Test Quality MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});
