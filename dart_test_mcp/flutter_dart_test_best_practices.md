# Flutter ve Dart Test Kodları: Kapsamlı En İyi Pratikler ve Anti-Pattern Rehberi

Flutter ve Dart ekosisteminde **test kalitesi, uygulama güvenilirliğinin temel taşıdır**. Araştırmalar, AI tarafından üretilen test kodlarının gerçek senaryolarda yalnızca %47,1 başarı oranına sahip olduğunu ve zayıf assertion'lar, eksik edge case'ler ve production kod pratiklerinin yanlış uygulanması gibi sistematik hatalar içerdiğini gösteriyor. Bu rehber, Flutter/Dart test yazımında bulunması ve bulunmaması gereken özellikleri, AI'ın düştüğü yaygın tuzakları ve test kalitesini artıran teknikleri kod örnekleriyle detaylı şekilde ele alıyor.

## Test kodlarında bulunması gereken temel özellikler

### Test organizasyonu ve yapısal best practices

Flutter test mimarisi, **Testing Pyramid** prensibine dayanır: %70 unit testler, %20 widget testler, %10 integration testler. Her test dosyası `_test.dart` eki ile bitmeli ve `test/` klasöründe `lib/` klasörünün yapısını yansıtmalıdır.

**Doğru proje yapısı:**
```dart
project_root/
  lib/
    features/
      auth/
        auth_service.dart
  test/
    features/
      auth/
        auth_service_test.dart
  integration_test/
    app_test.dart
```

**AAA (Arrange-Act-Assert) pattern'ı takip edin:**
```dart
test('Counter increments value correctly', () {
  // Arrange - Test verisini hazırla
  final counter = Counter();

  // Act - Test edilecek kodu çalıştır
  counter.increment();

  // Assert - Sonucu doğrula
  expect(counter.value, 1);
});
```

**group() ile ilişkili testleri organize edin:**
```dart
void main() {
  group('Counter operations', () {
    late Counter counter;

    setUp(() {
      counter = Counter();
    });

    tearDown(() {
      counter.dispose();
    });

    test('starts at zero', () {
      expect(counter.value, 0);
    });

    test('increments correctly', () {
      counter.increment();
      expect(counter.value, 1);
    });
  });
}
```

### Güçlü ve doğru assertion kullanımı

Flutter'ın matcher kütüphanesi, testlerde kullanılabilecek zengin bir assertion seti sunar. **Zayıf assertion'lar AI'ın en sık yaptığı hatalardan biridir**.

**✅ Güçlü assertion örneği:**
```dart
test('submits entry with correct values', () async {
  final testEntry = FoodEntry(
    name: 'Nasi Goreng',
    calories: 500,
    protein: 12,
  );

  when(() => mockRepository.saveFoodEntry(any())).thenAnswer((_) async {});

  await cubit.submitEntry(testEntry);

  // Spesifik değerleri doğrula
  verify(() => mockRepository.saveFoodEntry(argThat(
    isA<FoodEntry>()
      .having((e) => e.name, 'name', 'Nasi Goreng')
      .having((e) => e.calories, 'calories', 500)
      .having((e) => e.protein, 'protein', 12)
  ))).called(1);
});
```

**❌ Zayıf assertion (AI hatası):**
```dart
test('should save food entry', () async {
  // Sadece çağrıldığını kontrol eder, ne ile çağrıldığını değil
  verify(mockRepository.saveFoodEntry(any)).called(1);
});
```

**Temel matcher'lar:**
```dart
// Eşitlik
expect(result, equals(42));
expect(result, isA<User>());

// Sayısal karşılaştırmalar
expect(value, greaterThan(5));
expect(value, lessThan(10));
expect(value, closeTo(3.14, 0.01));

// Koleksiyon matcher'ları
expect(list, contains('item'));
expect(list, containsAll([1, 2, 3]));
expect(list, everyElement(isPositive));

// String matcher'ları
expect(text, startsWith('Hello'));
expect(text, matches(r'\d+'));

// Async matcher'lar
await expectLater(futureValue, completion(equals(expected)));
expect(stream, emitsInOrder([1, 2, 3, emitsDone]));

// Widget matcher'ları
expect(find.text('Hello'), findsOneWidget);
expect(find.byType(Button), findsNWidgets(2));
```

### Test isolation ve bağımsızlık prensipleri

**Her test tamamen bağımsız olmalı:**
```dart
// ❌ YANLIŞ - Testler birbirine bağımlı
var counter = 0;
test('first', () { counter++; expect(counter, 1); });
test('second', () { counter++; expect(counter, 2); }); // Sıra değişirse başarısız

// ✅ DOĞRU - Bağımsız testler
test('first', () {
  var counter = 0;
  counter++;
  expect(counter, 1);
});

test('second', () {
  var counter = 0;
  counter++;
  expect(counter, 1);
});
```

**Testler rastgele sırada çalışabilmeli:**
```bash
flutter test --test-randomize-ordering-seed=random
```

**Temel izolasyon kuralları:**
- Unit testler disk okuma/yazma yapmamalı
- Gerçek network çağrıları yapılmamalı
- Gerçek veritabanı erişimi olmamalı
- Tüm external bağımlılıklar mock'lanmalı

### Mock, stub ve fake kullanım stratejileri

**Mocktail kullanın (Mockito yerine):**
```yaml
dev_dependencies:
  mocktail: ^1.0.0  # Code generation gerektirmez
```

**Mock oluşturma:**
```dart
import 'package:mocktail/mocktail.dart';

class ApiService {
  Future<User> fetchUser(String id);
}

class MockApiService extends Mock implements ApiService {}
```

**Method stubbing:**
```dart
test('fetches user successfully', () async {
  final mockApi = MockApiService();
  final expectedUser = User(id: '1', name: 'John');

  // Method'u stub'la
  when(() => mockApi.fetchUser('1'))
      .thenAnswer((_) async => expectedUser);

  final user = await mockApi.fetchUser('1');

  expect(user, expectedUser);
});
```

**Interaction verification:**
```dart
test('service calls API with correct params', () async {
  final mockApi = MockApiService();

  when(() => mockApi.fetchUser(any()))
      .thenAnswer((_) async => User());

  await service.loadUser('123');

  verify(() => mockApi.fetchUser('123')).called(1);
  verifyNever(() => mockApi.fetchUser('456'));
});
```

**Argument capturing:**
```dart
setUpAll(() {
  registerFallbackValue(FakeUser());
});

test('captures passed arguments', () {
  when(() => api.saveUser(captureAny()))
      .thenAnswer((_) async => true);

  service.saveUser(testUser);

  final captured = verify(
    () => api.saveUser(captureAny())
  ).captured;

  expect(captured.first.name, 'John');
});
```

**Ne zaman mock kullanılmalı:**
- ✅ External dependencies: Database, network, file system, time
- ❌ Value objects: POJOs, data classes
- ❌ Pure functions: Hesaplamalar, formatting, validation
- ✅ I/O operations, ❌ Logic

### Widget testing best practices

**Temel widget test yapısı:**
```dart
testWidgets('displays title and message', (tester) async {
  await tester.pumpWidget(
    MaterialApp(
      home: MyWidget(
        title: 'Test',
        message: 'Hello',
      ),
    ),
  );

  expect(find.text('Test'), findsOneWidget);
  expect(find.text('Hello'), findsOneWidget);
});
```

**Pump methodları:**
```dart
// pumpWidget() - İlk render (bir kez çağrılır)
await tester.pumpWidget(MyApp());

// pump() - Tek frame rebuild
await tester.pump();
await tester.pump(Duration(seconds: 1)); // Zamanı ilerlet

// pumpAndSettle() - Tüm animasyonların bitmesini bekle
await tester.tap(find.byType(Button));
await tester.pumpAndSettle();
```

**Widget bulma stratejileri:**
```dart
// Type ile
find.byType(ElevatedButton)

// Text ile
find.text('Click me')

// Key ile (önerilen)
find.byKey(Key('my_widget'))

// Icon ile
find.byIcon(Icons.add)

// Descendants
find.descendant(
  of: find.byType(AppBar),
  matching: find.text('Title'),
)
```

**Key kullanımı best practice:**
```dart
// Widget'ta
FloatingActionButton(
  key: const ValueKey('increment'),
  onPressed: () => counter++,
)

// Test'te
await tester.tap(find.byKey(const ValueKey('increment')));
```

**Golden file testing:**
```dart
testWidgets('matches golden', (tester) async {
  await tester.pumpWidget(MyWidget());

  await expectLater(
    find.byType(MyWidget),
    matchesGoldenFile('goldens/my_widget.png'),
  );
});
```

## Test kodlarında bulunmaması gereken anti-pattern'ler

### Try-catch bloklarının test kodlarındaki zararları

**En kritik anti-pattern: Try-catch blokları testlerde kullanılmamalı.** AI araçları, production kod pattern'lerini testlere uygulayarak bu hatayı sistematik olarak yapar.

**❌ ÇOK YANLIŞ - AI tarafından üretilen kod:**
```dart
test('testSomething', () {
  try {
    someMethod();
    expect(result, expectedValue);
  } catch (Exception e) {
    fail('Test failed with exception: $e');
  }
});
```

**Neden zararlı:**
- **Gerçek hataları gizler**: Exception'lar yakalandığında test framework doğru şekilde raporlayamaz
- **Yanıltıcı hata mesajları**: Custom mesajlar framework'ün otomatik mesajlarından daha az bilgilendirici
- **Test framework tasarımını bozar**: Framework'ler exception'ları otomatik olarak ele almak için tasarlanmıştır
- **Stack trace kaybı**: Dart'ta stack trace exception'dan ayrıdır ve try-catch ile kaybolur

**✅ DOĞRU yaklaşım:**

**Hata fırlatmaması gereken testler için:**
```dart
test('successful operation', () {
  // Try-catch kullanma - framework handle eder
  final result = repository.getData();
  expect(result, isNotNull);
  expect(result.length, greaterThan(0));
});
```

**Hata fırlatması gereken testler için:**
```dart
test('throws ArgumentError for invalid input', () {
  expect(
    () => calculator.divide(10, 0),
    throwsA(isA<ArgumentError>()),
  );
});

test('throws specific exception with message', () {
  expect(
    () => validateAge(-1),
    throwsA(predicate((e) =>
      e is ArgumentError &&
      e.message.contains('positive')
    )),
  );
});
```

### Test kodlarında logic içermesi sorunu

**Test kodu production kodu gibi yazılmamalı.** Test'ler basit, lineer ve açık olmalıdır.

**❌ YANLIŞ - Logic içeren test:**
```dart
test('validates users', () {
  final users = generateTestUsers();
  int validCount = 0;

  for (final user in users) {
    try {
      if (validator.validate(user)) {
        validCount++;
      }
    } catch (e) {
      // handle error
    }
  }

  expect(validCount, greaterThan(0));
});
```

**Sorunlar:**
- If-else, loop, switch gibi kontrol akış yapıları
- Test'in kendisinde bug olabilir
- Hangi senaryo başarısız oldu anlaşılmaz
- Karmaşık ve anlaşılması zor

**✅ DOĞRU - Basit, lineer testler:**
```dart
test('validates user with valid email and age over 18', () {
  final user = User(
    name: 'John Doe',
    email: 'john@example.com',
    age: 25,
  );

  final result = validator.validate(user);

  expect(result.isValid, isTrue);
});

test('rejects user with invalid email format', () {
  final user = User(
    name: 'John Doe',
    email: 'not-an-email',
    age: 25,
  );

  final result = validator.validate(user);

  expect(result.isValid, isFalse);
  expect(result.errors, contains('Invalid email format'));
});

test('rejects user under 18 years old', () {
  final user = User(
    name: 'Jane Doe',
    email: 'jane@example.com',
    age: 16,
  );

  final result = validator.validate(user);

  expect(result.isValid, isFalse);
  expect(result.errors, contains('Must be 18 or older'));
});
```

### Flaky test problemleri ve nedenleri

**Flaky testler bazen geçer bazen başarısız olur.** Ana nedenler:

**1. Timing sorunları:**
```dart
// ❌ YANLIŞ - Race condition
test('loads data', () async {
  service.loadData();
  // pump() yetersiz - animasyon tamamlanmamış olabilir
  await tester.pump();
  expect(find.text('Data'), findsOneWidget);
});

// ✅ DOĞRU
test('loads data', () async {
  service.loadData();
  await tester.pumpAndSettle(); // Tüm animasyonlar bitene kadar bekle
  expect(find.text('Data'), findsOneWidget);
});
```

**2. Test sırası bağımlılığı:**
```dart
// ❌ YANLIŞ - Shared state
class SharedState {
  static int counter = 0;
}

test('first', () {
  SharedState.counter++;
  expect(SharedState.counter, 1);
});

test('second', () {
  SharedState.counter++;
  expect(SharedState.counter, 2); // Sıra değişirse fail
});

// ✅ DOĞRU - Her test bağımsız
test('first', () {
  final counter = Counter();
  counter.increment();
  expect(counter.value, 1);
});
```

**3. External bağımlılıklar:**
```dart
// ❌ YANLIŞ - Gerçek network call
test('fetches data', () async {
  final data = await api.fetchFromServer(); // Flaky!
  expect(data, isNotNull);
});

// ✅ DOĞRU - Mock kullan
test('fetches data', () async {
  when(() => mockApi.fetchFromServer())
      .thenAnswer((_) async => testData);

  final data = await service.fetchData();
  expect(data, testData);
});
```

### Over-mocking ve under-mocking sorunları

**Over-mocking: Gereksiz mock kullanımı**

**❌ YANLIŞ - Basit hesaplama mock'lanıyor:**
```dart
test('calculates total price', () {
  final mockCalculator = MockPriceCalculator();
  when(mockCalculator.multiply(any, any)).thenReturn(100.0);
  when(mockCalculator.add(any, any)).thenReturn(110.0);

  final cart = ShoppingCart(calculator: mockCalculator);
  final total = cart.calculateTotal();

  // Mock'ları test ediyoruz, gerçek kodu değil!
  expect(total, equals(110.0));
});
```

**✅ DOĞRU - Gerçek objeler kullan:**
```dart
test('calculates total price', () {
  final cart = ShoppingCart();
  cart.addItem(Item(price: 10.0, quantity: 10));
  cart.addItem(Item(price: 5.0, quantity: 2));

  final total = cart.calculateTotal();

  expect(total, equals(110.0));
});
```

**Under-mocking: Yetersiz mock kullanımı**

```dart
// ❌ YANLIŞ - External dependency mock'lanmamış
test('saves to database', () async {
  final repository = UserRepository(); // Gerçek DB bağlantısı!
  await repository.save(testUser);
  // Slow, flaky, external bağımlı
});

// ✅ DOĞRU
test('saves to database', () async {
  final mockDb = MockDatabase();
  final repository = UserRepository(mockDb);

  when(() => mockDb.save(any())).thenAnswer((_) async {});

  await repository.save(testUser);

  verify(() => mockDb.save(testUser)).called(1);
});
```

### Test bağımlılıkları ve coupling problemleri

**❌ YANLIŞ - Concrete dependency:**
```dart
class UserService {
  final ApiClient api = ApiClient(); // Hard-coded dependency

  Future<User> getUser(String id) => api.fetch(id);
}

// Test edilemez!
```

**✅ DOĞRU - Dependency injection:**
```dart
class UserService {
  final ApiClient api;
  UserService(this.api); // Constructor injection

  Future<User> getUser(String id) => api.fetch(id);
}

test('fetches from API', () async {
  final mockApi = MockApiClient();
  final service = UserService(mockApi);

  when(() => mockApi.fetch('123'))
      .thenAnswer((_) async => User(id: '123'));

  final user = await service.getUser('123');
  expect(user.id, '123');
});
```

### Hardcoded değerler ve magic number kullanımı

**Test kodlarında magic number kabul edilebilir - clarity > DRY**

```dart
// ✅ Test'te açık değerler kullanmak OK
test('calculates discount', () {
  final price = 100.0;
  final discountRate = 0.2;

  final discounted = calculateDiscount(price, discountRate);

  expect(discounted, equals(80.0)); // Magic number OK
});

// ❌ Gereksiz abstraction
const EXPECTED_DISCOUNTED_PRICE = 80.0; // Overkill
```

**Ancak test data için builder pattern kullanabilirsiniz:**
```dart
class UserBuilder {
  String name = 'Test User';
  String email = 'test@example.com';
  int age = 25;

  UserBuilder withName(String name) {
    this.name = name;
    return this;
  }

  UserBuilder withAge(int age) {
    this.age = age;
    return this;
  }

  User build() => User(name: name, email: email, age: age);
}

test('validates adult users', () {
  final user = UserBuilder()
      .withAge(25)
      .build();

  expect(validator.validate(user), isTrue);
});
```

### Async test anti-pattern'leri

**❌ YANLIŞ - Await unutulmuş:**
```dart
test('async operation', () async {
  service.loadData(); // await eksik!
  expect(service.data, isNotNull); // Fail - henüz yüklenmedi
});
```

**✅ DOĞRU:**
```dart
test('async operation', () async {
  await service.loadData();
  expect(service.data, isNotNull);
});
```

**Stream testing:**
```dart
test('stream emits values', () async {
  final stream = countStream();

  await expectLater(
    stream,
    emitsInOrder([1, 2, 3, emitsDone]),
  );
});

test('stream handles errors', () async {
  expect(
    errorStream(),
    emitsError(isA<CustomException>()),
  );
});
```

## AI'ın test kodu yazarken yaptığı yaygın hatalar

### Gereksiz try-catch blokları ekleme

**AI'ın en yaygın hatası:** Production kodda iyi pratik olan try-catch'i testlere de uygular.

**❌ AI tarafından üretilen tipik kod:**
```dart
@Test
void testUserLogin() {
  try {
    final result = authService.login('user@test.com', 'pass');
    expect(result.isSuccess, isTrue);
  } catch (Exception e) {
    fail('Test failed: $e');
  }
}
```

**Çözüm:** Try-catch'i tamamen kaldırın ve framework'ün exception'ları ele almasına izin verin.

### Test assertion'larını zayıflatma

AI, test'lerin geçmesini önceliklendirir ancak doğrulamayı değil. Araştırmalar AI testlerinin "zayıf veya aşırı genel assertion'lar" içerdiğini gösteriyor.

**❌ AI tarafından üretilen zayıf assertion:**
```dart
test('processes data correctly', () {
  final result = processor.process(data);
  expect(result, isNotNull); // Çok zayıf!
  expect(result.fields, isNotEmpty); // Hala zayıf!
});
```

**✅ İnsan tarafından yazılan güçlü assertion:**
```dart
test('processes data with correct transformation', () {
  final result = processor.process(data);
  expect(result.id, equals('expected-id'));
  expect(result.value, equals(42));
  expect(result.timestamp, isA<DateTime>());
  expect(result.metadata['key'], equals('expected-value'));
});
```

**any() matcher'ın aşırı kullanımı:**
```dart
// ❌ AI hatası
verify(mockRepository.saveFoodEntry(any)).called(1);

// ✅ Doğru
verify(mockRepository.saveFoodEntry(argThat(
  isA<FoodEntry>()
    .having((e) => e.name, 'name', 'Nasi Goreng')
    .having((e) => e.calories, 'calories', 500)
))).called(1);
```

### Gerçek test senaryoları yerine happy path'e odaklanma

AI, happy path senaryolarına odaklanır çünkü eğitim verisi çoğunlukla başarılı senaryolar içerir. **Araştırmalar AI testlerinin gerçek kodda sadece %47,1 başarı oranına sahip olduğunu gösteriyor.**

**❌ AI tarafından üretilen yetersiz testler:**
```dart
test('user login works', () {
  final result = authService.login('user@example.com', 'password123');
  expect(result.isSuccess, isTrue);
});

// Eksik: empty inputs, invalid format, network errors, locked accounts
```

**✅ Kapsamlı test coverage:**
```dart
group('AuthService login', () {
  test('succeeds with valid credentials', () {
    final result = authService.login('user@example.com', 'ValidPass123');
    expect(result.isSuccess, isTrue);
  });

  test('fails with empty email', () {
    expect(
      () => authService.login('', 'password'),
      throwsA(isA<ValidationException>()),
    );
  });

  test('fails with invalid email format', () {
    expect(
      () => authService.login('not-an-email', 'password'),
      throwsA(isA<ValidationException>()),
    );
  });

  test('fails with wrong password', () {
    final result = authService.login('user@example.com', 'WrongPassword');
    expect(result.isSuccess, isFalse);
    expect(result.error, equals('Invalid credentials'));
  });

  test('handles network timeout', () async {
    when(mockApi.authenticate(any, any))
      .thenThrow(TimeoutException('timeout'));

    final result = await authService.login('user@example.com', 'password');
    expect(result.isSuccess, isFalse);
    expect(result.error, contains('timeout'));
  });
});
```

### Mock kullanımında aşırıya kaçma

AI, mock pattern'lerini her yerde uygular ve gereksiz mock'lar yaratır.

**Kural:** Sadece I/O operations'ları mock'layın, logic'i değil.

**✅ Mock kullanılması gereken yerler:**
- Database operations
- Network calls
- File system access
- Time/date operations
- Platform channels

**❌ Mock kullanılmaması gereken yerler:**
- Pure functions
- Calculations
- Formatters
- Validators
- Simple data transformations

### Test isimlerinde belirsizlik

AI generic template'ler kullanır: "test1", "testLogin", "Happy path 1" gibi anlamsız isimler.

**❌ AI tarafından üretilen generic isimler:**
```dart
test('test1', () { ... });
test('testWithdraw', () { ... });
test('should work', () { ... });
test('Happy path 1', () { ... }); // Gerçek AI output
```

**✅ Açıklayıcı test isimleri:**
```dart
test('withdraw decreases balance by withdrawn amount', () { ... });
test('withdraw throws ArgumentError when amount is negative', () { ... });
test('withdraw throws InsufficientFundsException when balance too low', () { ... });
```

**Test isimlendirme formülleri:**

**Given-When-Then:**
```dart
testWidgets(
  'GIVEN user is logged in '
  'WHEN user taps logout button '
  'THEN user is redirected to login screen',
  (tester) async { ... }
);
```

**Descriptive sentence (önerilen):**
```dart
test('adds item to cart when item is valid and in stock', () { ... });
test('throws OutOfStockException when item quantity is zero', () { ... });
```

### Edge case'leri göz ardı etme

AI sistematik olarak edge case'leri atlar.

**Edge case kategorileri:**

**1. Null ve empty değerler:**
```dart
group('handles null/empty values', () {
  test('throws when user is null', () {
    expect(() => service.process(null), throwsArgumentError);
  });

  test('throws when name is empty', () {
    final user = User(name: '', email: 'test@example.com');
    expect(() => service.process(user), throwsArgumentError);
  });
});
```

**2. Boundary değerleri:**
```dart
test('accepts minimum valid age of 18', () {
  final user = User(name: 'Test', age: 18);
  expect(validator.validate(user), isTrue);
});

test('rejects age of 17', () {
  final user = User(name: 'Test', age: 17);
  expect(validator.validate(user), isFalse);
});

test('rejects age over 120', () {
  final user = User(name: 'Test', age: 121);
  expect(validator.validate(user), isFalse);
});
```

**3. Özel karakterler:**
```dart
test('handles SQL injection attempts', () {
  final user = User(name: "'; DROP TABLE users; --");
  expect(() => repository.save(user), returnsNormally);
});

test('accepts names with emojis', () {
  final user = User(name: 'Test 😀');
  // Expected behavior tanımla
});
```

**4. Concurrent access:**
```dart
test('handles concurrent operations without corruption', () async {
  final users = List.generate(10, (i) => User(name: 'User$i'));

  await Future.wait(users.map((u) => repository.save(u)));

  final saved = await repository.getAll();
  expect(saved.length, equals(10));
  expect(saved.map((u) => u.name).toSet().length, equals(10));
});
```

## Test kalitesini artıran teknikler

### AAA (Arrange-Act-Assert) pattern

**En yaygın ve önerilen pattern:**

```dart
test('user registration creates new account', () {
  // ARRANGE - Test verisini hazırla
  final userData = {
    'email': 'test@example.com',
    'password': 'SecurePass123',
    'name': 'Test User',
  };
  final mockDb = MockDatabase();
  final service = AuthService(mockDb);

  when(() => mockDb.createUser(any()))
      .thenAnswer((_) async => User(id: '123'));

  // ACT - Tek bir aksiyon
  final result = await service.register(userData);

  // ASSERT - Sonuçları doğrula
  expect(result.isSuccess, isTrue);
  expect(result.user.id, equals('123'));
  verify(() => mockDb.createUser(any())).called(1);
});
```

### Given-When-Then yaklaşımı

**BDD (Behavior-Driven Development) stili:**

```dart
testWidgets(
  'GIVEN logged in user '
  'WHEN taps profile button '
  'THEN shows profile screen',
  (tester) async {
    // GIVEN
    final mockAuth = MockAuthService();
    when(() => mockAuth.isLoggedIn).thenReturn(true);

    await tester.pumpWidget(
      MaterialApp(
        home: HomeScreen(auth: mockAuth),
      ),
    );

    // WHEN
    await tester.tap(find.byIcon(Icons.person));
    await tester.pumpAndSettle();

    // THEN
    expect(find.byType(ProfileScreen), findsOneWidget);
  }
);
```

### Test data builder pattern

```dart
class UserTestBuilder {
  String _name = 'Test User';
  String _email = 'test@example.com';
  int _age = 25;
  bool _isActive = true;

  UserTestBuilder withName(String name) {
    _name = name;
    return this;
  }

  UserTestBuilder withEmail(String email) {
    _email = email;
    return this;
  }

  UserTestBuilder withAge(int age) {
    _age = age;
    return this;
  }

  UserTestBuilder inactive() {
    _isActive = false;
    return this;
  }

  User build() => User(
    name: _name,
    email: _email,
    age: _age,
    isActive: _isActive,
  );
}

// Kullanımı
test('validates adult users', () {
  final user = UserTestBuilder()
      .withAge(25)
      .build();

  expect(validator.validate(user), isTrue);
});

test('rejects inactive users', () {
  final user = UserTestBuilder()
      .inactive()
      .build();

  expect(validator.validate(user), isFalse);
});
```

### Proper test naming conventions

**Formül: [Method/Feature] [Scenario] [Expected Result]**

```dart
// ✅ Mükemmel isimler
test('increment adds one to current value', () {});
test('divide throws ArgumentError when divisor is zero', () {});
test('fetchUser returns cached user when available', () {});
test('login fails with InvalidCredentialsException for wrong password', () {});

// ❌ Kötü isimler
test('test1', () {});
test('it works', () {});
test('check user', () {});
```

**Widget test isimlendirme:**
```dart
testWidgets(
  'counter displays zero initially and increments on tap',
  (tester) async { ... }
);

testWidgets(
  'login form shows error message when email is invalid',
  (tester) async { ... }
);
```

### Test maintainability prensipleri

**1. DRY'ı aşırıya kaçırmayın:**
```dart
// Test'lerde tekrar kabul edilebilir
test('scenario 1', () {
  final user = User(name: 'John', age: 25);
  expect(validator.validate(user), isTrue);
});

test('scenario 2', () {
  final user = User(name: 'Jane', age: 30);
  expect(validator.validate(user), isTrue);
});
```

**2. Test utilities kullanın:**
```dart
// Test helper functions
Future<void> pumpAndSettle(WidgetTester tester, Widget widget) async {
  await tester.pumpWidget(MaterialApp(home: widget));
  await tester.pumpAndSettle();
}

// Kullanımı
testWidgets('test', (tester) async {
  await pumpAndSettle(tester, MyWidget());
  // ...
});
```

**3. Custom matchers oluşturun:**
```dart
Matcher hasValue(Object? valueOrMatcher) {
  return isA<Result>()
      .having((r) => r.value, 'value', valueOrMatcher);
}

test('returns successful result', () {
  expect(result, hasValue(42));
});
```

### Flutter specific testing utilities

**pumpWidget, pump, pumpAndSettle:**

```dart
testWidgets('animation test', (tester) async {
  // İlk render
  await tester.pumpWidget(MyAnimatedWidget());

  // Animasyonu başlat
  await tester.tap(find.byType(Button));

  // Tek frame
  await tester.pump();

  // 100ms ilerlet
  await tester.pump(Duration(milliseconds: 100));

  // Tüm animasyonlar bitene kadar bekle
  await tester.pumpAndSettle();

  expect(find.text('Complete'), findsOneWidget);
});
```

**scrollUntilVisible:**
```dart
testWidgets('scrolls to item', (tester) async {
  await tester.pumpWidget(MyListView());

  await tester.scrollUntilVisible(
    find.text('Item 50'),
    500.0, // scroll distance
    scrollable: find.byType(ListView),
  );

  expect(find.text('Item 50'), findsOneWidget);
});
```

**enterText:**
```dart
testWidgets('enters text in field', (tester) async {
  await tester.pumpWidget(MyForm());

  await tester.enterText(
    find.byKey(Key('email')),
    'test@example.com',
  );

  expect(find.text('test@example.com'), findsOneWidget);
});
```

### Golden tests ve snapshot testing

**Golden test nedir:**
Widget'ın görsel snapshot'ını alıp gelecekteki değişiklikleri kontrol eder.

```dart
testWidgets('matches golden file', (tester) async {
  await tester.pumpWidget(
    MaterialApp(
      home: MyComplexWidget(
        title: 'Test',
        subtitle: 'Golden test',
      ),
    ),
  );

  await expectLater(
    find.byType(MyComplexWidget),
    matchesGoldenFile('goldens/my_widget.png'),
  );
});
```

**Golden test güncelleme:**
```bash
flutter test --update-goldens
```

**Best practices:**
- Platform-specific golden'lar oluşturun
- CI/CD'de golden testler önemli
- Büyük UI değişikliklerini yakalar
- Font rendering farklılıklarına dikkat

## Spesifik Flutter test konuları

### Widget testing best practices

**Key kullanımı:**
```dart
// Widget'ta
TextField(
  key: Key('email_input'),
  decoration: InputDecoration(labelText: 'Email'),
)

// Test'te
await tester.enterText(
  find.byKey(Key('email_input')),
  'test@example.com',
);
```

**Semantics testing:**
```dart
testWidgets('has correct semantics', (tester) async {
  await tester.pumpWidget(MyButton());

  final semantics = tester.getSemantics(find.byType(MyButton));
  expect(semantics.label, 'Submit');
  expect(semantics.isButton, isTrue);
  expect(semantics.isEnabled, isTrue);
});
```

**Platform-specific testing:**
```dart
testWidgets('shows correct platform widget', (tester) async {
  await tester.pumpWidget(
    MaterialApp(
      home: Theme(
        data: ThemeData(platform: TargetPlatform.iOS),
        child: MyWidget(),
      ),
    ),
  );

  expect(find.byType(CupertinoButton), findsOneWidget);
});
```

### Integration test yazım teknikleri

**Setup:**
```yaml
dev_dependencies:
  integration_test:
    sdk: flutter
```

**Tam end-to-end flow:**
```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:my_app/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Shopping flow', () {
    testWidgets('complete purchase flow', (tester) async {
      app.main();
      await tester.pumpAndSettle();

      // Browse
      await tester.tap(find.text('Products'));
      await tester.pumpAndSettle();

      // Add to cart
      await tester.tap(find.byIcon(Icons.add_shopping_cart).first);
      await tester.pumpAndSettle();

      // Checkout
      await tester.tap(find.byIcon(Icons.shopping_cart));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Checkout'));
      await tester.pumpAndSettle();

      // Verify
      expect(find.text('Order placed!'), findsOneWidget);
    });
  });
}
```

**Page Object Pattern:**
```dart
class LoginPage {
  final WidgetTester tester;
  LoginPage(this.tester);

  Future<void> enterEmail(String email) async {
    await tester.enterText(find.byKey(Key('email')), email);
  }

  Future<void> enterPassword(String password) async {
    await tester.enterText(find.byKey(Key('password')), password);
  }

  Future<void> tapLogin() async {
    await tester.tap(find.text('Login'));
    await tester.pumpAndSettle();
  }
}

testWidgets('login flow', (tester) async {
  final loginPage = LoginPage(tester);

  await loginPage.enterEmail('test@example.com');
  await loginPage.enterPassword('password');
  await loginPage.tapLogin();

  expect(find.text('Welcome'), findsOneWidget);
});
```

### State management testing

**Bloc testing:**
```dart
import 'package:bloc_test/bloc_test.dart';

blocTest<CounterBloc, int>(
  'emits [1] when increment added',
  build: () => CounterBloc(),
  act: (bloc) => bloc.add(CounterIncrementPressed()),
  expect: () => [1],
);

blocTest<AuthBloc, AuthState>(
  'emits loading then success on login',
  build: () {
    when(() => mockAuthRepo.login(any(), any()))
        .thenAnswer((_) async => User(id: '1'));
    return AuthBloc(authRepository: mockAuthRepo);
  },
  act: (bloc) => bloc.add(LoginRequested('email', 'pass')),
  expect: () => [
    AuthLoading(),
    AuthSuccess(User(id: '1')),
  ],
  verify: (_) {
    verify(() => mockAuthRepo.login('email', 'pass')).called(1);
  },
);
```

**Mock Bloc:**
```dart
class MockCounterBloc extends MockBloc<CounterEvent, int>
    implements CounterBloc {}

testWidgets('widget with mock bloc', (tester) async {
  final mockBloc = MockCounterBloc();
  whenListen(mockBloc, Stream.fromIterable([0, 1, 2]), initialState: 0);

  await tester.pumpWidget(
    BlocProvider.value(
      value: mockBloc,
      child: MaterialApp(home: CounterPage()),
    ),
  );

  expect(find.text('0'), findsOneWidget);
});
```

**Provider testing:**
```dart
testWidgets('Provider updates widget', (tester) async {
  final model = MyModel();

  await tester.pumpWidget(
    ChangeNotifierProvider.value(
      value: model,
      child: MaterialApp(
        home: Consumer<MyModel>(
          builder: (context, myModel, _) => Text('${myModel.value}'),
        ),
      ),
    ),
  );

  expect(find.text('0'), findsOneWidget);

  model.increment();
  await tester.pump();

  expect(find.text('1'), findsOneWidget);
});
```

**Riverpod testing:**
```dart
test('provider returns value', () {
  final container = ProviderContainer();
  addTearDown(container.dispose);

  expect(container.read(helloWorldProvider), 'Hello world');
});

test('overriding provider', () {
  final container = ProviderContainer(
    overrides: [
      exampleProvider.overrideWith((ref) => 'Test value'),
    ],
  );

  expect(container.read(exampleProvider), 'Test value');
});

testWidgets('Riverpod widget test', (tester) async {
  await tester.pumpWidget(
    ProviderScope(
      child: MaterialApp(home: MyWidget()),
    ),
  );

  final container = ProviderScope.containerOf(
    tester.element(find.byType(MyWidget)),
  );

  expect(container.read(provider), 'expected');
});
```

### Navigation testing

**GoRouter testing:**
```dart
testWidgets('navigates to detail screen', (tester) async {
  final router = GoRouter(
    routes: [
      GoRoute(
        path: '/',
        builder: (_, __) => HomeScreen(),
      ),
      GoRoute(
        path: '/detail/:id',
        builder: (_, state) => DetailScreen(
          id: state.pathParameters['id']!,
        ),
      ),
    ],
  );

  await tester.pumpWidget(
    MaterialApp.router(routerConfig: router),
  );

  await tester.tap(find.text('Go to Detail'));
  await tester.pumpAndSettle();

  expect(find.byType(DetailScreen), findsOneWidget);
});
```

**Mock GoRouter:**
```dart
class MockGoRouter extends Mock implements GoRouter {}

testWidgets('calls navigation', (tester) async {
  final mockRouter = MockGoRouter();

  await tester.pumpWidget(
    InheritedGoRouter(
      goRouter: mockRouter,
      child: MaterialApp(home: MyScreen()),
    ),
  );

  await tester.tap(find.text('Navigate'));

  verify(() => mockRouter.go('/detail/1')).called(1);
});
```

### Async operation testing

**Future testing:**
```dart
test('completes successfully', () async {
  await expectLater(
    Future.value(42),
    completion(equals(42)),
  );
});

test('throws error', () async {
  await expectLater(
    Future.error(Exception('error')),
    throwsException,
  );
});
```

**Stream testing:**
```dart
test('stream emits in order', () async {
  final stream = Stream.fromIterable([1, 2, 3]);

  await expectLater(
    stream,
    emitsInOrder([1, 2, 3]),
  );
});

test('stream handles errors', () async {
  final stream = Stream<int>.error(Exception('error'));

  await expectLater(
    stream,
    emitsError(isException),
  );
});

test('stream completes', () async {
  final stream = Stream.fromIterable([1, 2]);

  await expectLater(
    stream,
    emitsInOrder([emits(1), emits(2), emitsDone]),
  );
});
```

**FakeAsync for time-based tests:**
```dart
import 'package:fake_async/fake_async.dart';

test('debounce test', () {
  fakeAsync((async) {
    final results = <int>[];

    Stream.fromIterable([1, 2, 3])
        .debounceTime(Duration(milliseconds: 500))
        .listen(results.add);

    async.elapse(Duration(milliseconds: 500));

    expect(results, [3]);
  });
});
```

## Özet ve en iyi pratikler

### Altın kurallar

**1. Test piramidi:** %70 unit, %20 widget, %10 integration

**2. FIRST prensipleri:**
- **F**ast: Testler hızlı çalışmalı
- **I**ndependent: Her test bağımsız
- **R**epeatable: Her ortamda çalışmalı
- **S**elf-validating: Otomatik pass/fail
- **T**imely: Kodla birlikte yazılmalı

**3. Test anatomisi:**
```dart
test('descriptive name explaining scenario and expectation', () {
  // Arrange: Setup
  // Act: Execute
  // Assert: Verify
});
```

**4. Coverage hedefleri:**
- Unit tests: >80%
- Critical paths: 100%
- Edge cases: Kapsamlı
- Integration: Ana user journeys

**5. CI/CD entegrasyonu:**
```bash
flutter test --coverage
flutter test --test-randomize-ordering-seed=random
```

### AI testlerini düzeltme checklist'i

- [ ] Try-catch bloklarını kaldırın
- [ ] any() yerine spesifik matcher'lar kullanın
- [ ] Test isimlerini açıklayıcı yapın
- [ ] Edge case'ler ekleyin
- [ ] Mock'ları sadece I/O için kullanın
- [ ] Logic'i test'lerden çıkarın
- [ ] Her testin tek bir sorumluluğu olsun
- [ ] Assertion'ları güçlendirin

### Önemli kaynaklar

- **Flutter Testing**: https://docs.flutter.dev/testing
- **Dart Testing**: https://dart.dev/tools/testing
- **flutter_test API**: https://api.flutter.dev/flutter/flutter_test/
- **bloc_test**: https://pub.dev/packages/bloc_test
- **mocktail**: https://pub.dev/packages/mocktail

## Sonuç

Flutter ve Dart'ta kaliteli test yazmak, **disiplin, pattern bilgisi ve AI'ın yaygın hatalarından kaçınma** becerisini gerektirir. Bu rehberde ele alınan prensipler ve örnekler, güvenilir, bakımı kolay ve kapsamlı test suite'leri oluşturmanızı sağlar.

**핵심 çıkarımlar:**
- Test'ler production koddan farklı yazılmalıdır - basit, lineer ve açık
- Try-catch blokları test kodlarında asla kullanılmamalı
- AI tarafından üretilen testler sistematik olarak gözden geçirilmeli
- Edge case'ler ve error senaryoları sistematik olarak test edilmeli
- Mock kullanımı stratejik olmalı - sadece external dependencies
- Strong assertion'lar ve descriptive test names kalıcı değer sağlar

Test yazmak sadece bug bulmak değil, aynı zamanda kod tasarımını iyileştirmek ve gelecekteki geliştiriciler için dokümantasyon sağlamaktır. Bu prensipleri takip ederek, Flutter uygulamalarınız güvenilir, bakımı kolay ve yüksek kalitede olacaktır.
