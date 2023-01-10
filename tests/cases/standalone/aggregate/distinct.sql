CREATE TABLE test (a INTEGER, b INTEGER, t BIGINT TIME INDEX);

INSERT INTO test VALUES (11, 22, 1), (13, 22, 2), (11, 21, 3), (11, 22, 4);

SELECT DISTINCT a, b FROM test ORDER BY a, b;

SELECT DISTINCT test.a, b FROM test ORDER BY a, b;

SELECT DISTINCT a FROM test ORDER BY a;

SELECT DISTINCT b FROM test ORDER BY b;

SELECT DISTINCT a, SUM(B) FROM test GROUP BY a ORDER BY a;

SELECT DISTINCT MAX(b) FROM test GROUP BY a;

SELECT DISTINCT CASE WHEN a > 11 THEN 11 ELSE a END FROM test;

DROP TABLE test;
